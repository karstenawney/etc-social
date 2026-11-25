"""
server.py - HTTP API for the social platform.

Run:
    pip install flask
    python server.py            # dev server, http://127.0.0.1:8000
    # for production, put this behind gunicorn + nginx (TLS termination at nginx)

All shared state lives in module-level dicts, exactly like the original
social.py. Because Flask's dev server (threaded=True) and gunicorn with
multiple threads/workers can call into this module concurrently, every
function that reads OR writes shared state acquires STATE_LOCK first.
This makes each operation atomic from the outside: no request can observe
or mutate state mid-way through another request's read-modify-write.

Design notes:
- uid / bid / pid are raw bytes internally, hex-encoded over the wire.
- Sessions (sid) are returned to the client once, at login, and must be
  sent back on every authenticated request via the X-Uid / X-Sid headers.
  (A browser client would use httponly cookies instead - see the note in
  create_app() below.)
- The lock is a single coarse RLock. This is the simplest possible
  correctness guarantee (equivalent to giving the whole app a GIL for its
  own state) and is fine at the traffic levels this in-memory design can
  handle at all. If you outgrow it, the real fix is moving state into a
  proper database (e.g. SQLite/Postgres) and letting the DB engine manage
  concurrency - a coarse lock does not scale across multiple processes.
"""

import hashlib
import hmac
import os
import pickle
import re
import secrets
import threading
import time

from flask import Flask, jsonify, request

# ---------------------------------------------------------------------------
# State + the lock that protects it
# ---------------------------------------------------------------------------

STATE_LOCK = threading.RLock()

SAVE_PATH = "save.pkl"
SESSION_TTL_SECONDS = 1800


def initialize_platform():
    global users, admins, posts, views, followers, following, saved_posts
    global followed_boards, boards, user_posts, board_posts, sessions, accounts
    global feed, keywords
    with STATE_LOCK:
        users = {}
        admins = {}
        posts = {}
        views = {}
        followers = {}
        following = {}
        saved_posts = {}
        followed_boards = {}
        boards = {}
        user_posts = {}
        board_posts = {}
        sessions = {}
        accounts = {}
        feed = {}
        keywords = {}


def save_platform():
    with STATE_LOCK:
        data = [users, admins, posts, views, followers, following, saved_posts,
                followed_boards, boards, user_posts, board_posts, sessions,
                accounts, feed, keywords]
        # Write to a temp file then atomically rename, so a crash mid-write
        # (or a request reading the file concurrently) never sees a
        # half-written save.
        tmp_path = SAVE_PATH + ".tmp"
        with open(tmp_path, "wb") as f:
            pickle.dump(data, f)
        os.replace(tmp_path, SAVE_PATH)


def load_save(savename):
    global users, admins, posts, views, followers, following, saved_posts
    global followed_boards, boards, user_posts, board_posts, sessions, accounts
    global feed, keywords
    with STATE_LOCK:
        with open(savename, "rb") as f:
            data = pickle.load(f)
        (users, admins, posts, views, followers, following, saved_posts,
         followed_boards, boards, user_posts, board_posts, sessions,
         accounts, feed, keywords) = data


# ---------------------------------------------------------------------------
# Pure helpers (no shared state -> no locking needed)
# ---------------------------------------------------------------------------

def get_uid(username):
    return hashlib.sha256(username.encode("utf-8")).digest()


def get_pid(uid, date_created):
    return bytes(x ^ y for x, y in zip(
        uid, hashlib.sha256(date_created.to_bytes(8, byteorder="big")).digest()))


def get_bid(creator_uid, board_name):
    return bytes(x ^ y for x, y in zip(
        creator_uid, hashlib.sha256(board_name.encode("utf-8")).digest()))


def get_passhash(password, salt=None):
    if salt is None:
        salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 200_000)
    return salt + digest


def check_password(password, stored):
    salt, digest = stored[:16], stored[16:]
    candidate = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 200_000)
    return hmac.compare_digest(digest, candidate)


def get_keywords(post_text):
    post_text = post_text.lower()
    post_text = re.sub(r"[^a-z\s]", "", post_text)
    post_text = re.sub(r"\b(un|re|in|im|il|ir|dis)(?=\w{3,}\b)", "", post_text)
    post_text = re.sub(r"(?<=\w{3})(s|es|ed|ing|ly)\b", "", post_text)
    return set(post_text.split())


# ---------------------------------------------------------------------------
# Stateful operations - every one of these acquires STATE_LOCK.
# Each function does its full read-check-write cycle while holding the
# lock, so e.g. "check username doesn't exist, then create it" can't race
# against another request doing the same check for the same username.
# ---------------------------------------------------------------------------

def create_user(username, name, description, password):
    with STATE_LOCK:
        uid = get_uid(username)
        if uid in users:
            return None, "Username exists"
        users[uid] = (username, name, description)
        followers[uid] = set()
        following[uid] = set()
        saved_posts[uid] = set()
        followed_boards[uid] = set()
        user_posts[uid] = set()
        accounts[uid] = get_passhash(password)
        feed[uid] = []
        return uid, None


def check_user_auth(uid, sid):
    with STATE_LOCK:
        if uid not in sessions:
            return False
        stored_sid, expiry = sessions[uid]
        if time.time() > expiry:
            del sessions[uid]
            return False
        try:
            return hmac.compare_digest(stored_sid, sid)
        except TypeError:
            return False


def deauth_user(uid):
    with STATE_LOCK:
        sessions.pop(uid, None)


def auth_user(uid, password):
    with STATE_LOCK:
        if uid in accounts and check_password(password, accounts[uid]):
            sid = secrets.token_bytes(32)
            sessions[uid] = (sid, int(time.time()) + SESSION_TTL_SECONDS)
            return sid
        return None


def create_board(sid, creator_uid, board_name, board_description,
                  is_whitelisted, whitelist, blacklist):
    with STATE_LOCK:
        if not check_user_auth(creator_uid, sid):
            return None, "Not authenticated"
        bid = get_bid(creator_uid, board_name)
        if bid in boards:
            return None, "Board exists"
        boards[bid] = (creator_uid, board_name, board_description,
                        is_whitelisted, whitelist, blacklist)
        board_posts[bid] = set()
        return bid, None


def create_post(sid, uid, bid, post_name, post_description, post_content, date_created):
    with STATE_LOCK:
        if not check_user_auth(uid, sid):
            return None, "Not authenticated"
        pid = get_pid(uid, date_created)
        if pid in posts:
            return None, "Post exists"
        if bid not in boards:
            return None, "Board does not exist"

        creator_uid, board_name, board_description, is_whitelisted, whitelist, blacklist = boards[bid]
        if uid in blacklist or (is_whitelisted and uid not in whitelist):
            return None, "User not allowed on board"

        posts[pid] = (uid, bid, post_name, post_description, post_content, date_created)
        views[pid] = 0
        board_posts[bid].add(pid)
        user_posts[uid].add(pid)
        for follower in followers[uid]:
            feed[follower].append(pid)
        keywords[pid] = get_keywords(f"{post_name} {post_description} {post_content}")
        return pid, None


def view_post(pid):
    with STATE_LOCK:
        if pid not in posts:
            return None
        uid, bid, name, desc, content, date = posts[pid]
        views[pid] += 1
        return {"title": name, "description": desc, "content": content,
                "date_created": date, "views": views[pid],
                "author_uid": uid.hex(), "board_id": bid.hex()}


def get_board_metadata(bid):
    with STATE_LOCK:
        if bid not in boards:
            return None
        creator_uid, name, desc, is_whitelisted, whitelist, blacklist = boards[bid]
        creator_username = users[creator_uid][0]
        return {"creator_username": creator_username, "board_name": name,
                "board_description": desc, "is_whitelisted": is_whitelisted}


def get_user_metadata(uid):
    with STATE_LOCK:
        if uid not in users:
            return None
        username, name, desc = users[uid]
        return {"username": username, "name": name, "description": desc}


def follow(sid, follower_uid, following_uid):
    with STATE_LOCK:
        if not check_user_auth(follower_uid, sid):
            return False, "Not authenticated"
        if following_uid not in users:
            return False, "User does not exist"
        following[follower_uid].add(following_uid)
        followers[following_uid].add(follower_uid)
        return True, None


def unfollow(sid, follower_uid, following_uid):
    with STATE_LOCK:
        if not check_user_auth(follower_uid, sid):
            return False, "Not authenticated"
        if following_uid not in users:
            return False, "User does not exist"
        following[follower_uid].discard(following_uid)
        followers[following_uid].discard(follower_uid)
        return True, None


def save_post(sid, uid, pid):
    with STATE_LOCK:
        if not check_user_auth(uid, sid):
            return False
        if pid in posts:
            saved_posts[uid].add(pid)
            return True
        return False


def unsave_post(sid, uid, pid):
    with STATE_LOCK:
        if not check_user_auth(uid, sid):
            return False
        saved_posts[uid].discard(pid)
        return True


def follow_board(sid, uid, bid):
    with STATE_LOCK:
        if not check_user_auth(uid, sid):
            return False
        if bid in boards:
            followed_boards[uid].add(bid)
            return True
        return False


def unfollow_board(sid, uid, bid):
    with STATE_LOCK:
        if not check_user_auth(uid, sid):
            return False
        followed_boards[uid].discard(bid)
        return True


def update_board_access(sid, uid, bid, is_whitelisted, whitelist, blacklist):
    with STATE_LOCK:
        if not check_user_auth(uid, sid):
            return False, "Not authenticated"
        if bid not in boards or boards[bid][0] != uid:
            return False, "Not the board owner"
        creator_uid, name, desc, _, _, _ = boards[bid]
        boards[bid] = (creator_uid, name, desc, is_whitelisted, whitelist, blacklist)
        return True, None


def pop_feed_item(sid, uid):
    """Atomically pop and return the oldest unread feed item for uid."""
    with STATE_LOCK:
        if not check_user_auth(uid, sid):
            return None, "Not authenticated"
        if not feed.get(uid):
            return None, None
        pid = feed[uid].pop(0)
        return pid, None


def peek_feed(sid, uid):
    with STATE_LOCK:
        if not check_user_auth(uid, sid):
            return None
        return list(feed.get(uid, []))


def get_top_n_matches(query, top_n=3, metric="jaccard"):
    with STATE_LOCK:
        scores = []
        for pid, kw in keywords.items():
            intersection = len(kw & query)
            if metric == "jaccard":
                union = len(kw | query)
                score = intersection / union if union else 0.0
            else:
                score = intersection
            if score > 0:
                scores.append((pid, score))
        scores.sort(key=lambda x: x[1], reverse=True)
        return scores[:top_n]


# ---------------------------------------------------------------------------
# HTTP layer
# ---------------------------------------------------------------------------

app = Flask(__name__)


def auth_from_headers():
    """Pull uid/sid out of request headers, hex-decoded."""
    uid_hex = request.headers.get("X-Uid", "")
    sid_hex = request.headers.get("X-Sid", "")
    try:
        return bytes.fromhex(uid_hex), bytes.fromhex(sid_hex)
    except ValueError:
        return b"", b""


@app.route("/api/signup", methods=["POST"])
def api_signup():
    data = request.get_json(force=True)
    uid, err = create_user(data["username"], data["name"], data["description"], data["password"])
    if err:
        return jsonify({"error": err}), 400
    sid = auth_user(uid, data["password"])
    return jsonify({"uid": uid.hex(), "sid": sid.hex()})


@app.route("/api/login", methods=["POST"])
def api_login():
    data = request.get_json(force=True)
    uid = get_uid(data["username"])
    sid = auth_user(uid, data["password"])
    if sid is None:
        return jsonify({"error": "Invalid username or password"}), 401
    return jsonify({"uid": uid.hex(), "sid": sid.hex()})


@app.route("/api/logout", methods=["POST"])
def api_logout():
    uid, _ = auth_from_headers()
    deauth_user(uid)
    return jsonify({"ok": True})


@app.route("/api/boards", methods=["POST"])
def api_create_board():
    uid, sid = auth_from_headers()
    data = request.get_json(force=True)
    whitelist = {bytes.fromhex(u) for u in data.get("whitelist", [])}
    blacklist = {bytes.fromhex(u) for u in data.get("blacklist", [])}
    bid, err = create_board(sid, uid, data["board_name"], data.get("board_description", ""),
                             data.get("is_whitelisted", False), whitelist, blacklist)
    if err:
        return jsonify({"error": err}), 400
    return jsonify({"board_id": bid.hex()})


@app.route("/api/boards/<owner_username>/<board_name>", methods=["GET"])
def api_get_board(owner_username, board_name):
    bid = get_bid(get_uid(owner_username), board_name)
    meta = get_board_metadata(bid)
    if meta is None:
        return jsonify({"error": "Board does not exist"}), 404
    with STATE_LOCK:
        pids = sorted(board_posts.get(bid, set()), key=lambda p: posts[p][5])
    meta["board_id"] = bid.hex()
    meta["post_ids"] = [p.hex() for p in pids]
    return jsonify(meta)


@app.route("/api/boards/<owner_username>/<board_name>/access", methods=["PUT"])
def api_update_board_access(owner_username, board_name):
    uid, sid = auth_from_headers()
    bid = get_bid(get_uid(owner_username), board_name)
    data = request.get_json(force=True)
    whitelist = {bytes.fromhex(u) for u in data.get("whitelist", [])}
    blacklist = {bytes.fromhex(u) for u in data.get("blacklist", [])}
    ok, err = update_board_access(sid, uid, bid, data.get("is_whitelisted", False), whitelist, blacklist)
    if not ok:
        return jsonify({"error": err}), 400
    return jsonify({"ok": True})


@app.route("/api/posts", methods=["POST"])
def api_create_post():
    uid, sid = auth_from_headers()
    data = request.get_json(force=True)
    owner_uid = get_uid(data["board_owner"])
    bid = get_bid(owner_uid, data["board_name"])
    pid, err = create_post(sid, uid, bid, data["post_name"], data.get("post_description", ""),
                            data.get("post_content", ""), int(time.time()))
    if err:
        return jsonify({"error": err}), 400
    return jsonify({"post_id": pid.hex()})


@app.route("/api/posts/<pid_hex>", methods=["GET"])
def api_get_post(pid_hex):
    post = view_post(bytes.fromhex(pid_hex))
    if post is None:
        return jsonify({"error": "Post does not exist"}), 404
    return jsonify(post)


@app.route("/api/posts/<pid_hex>/save", methods=["POST"])
def api_save_post(pid_hex):
    uid, sid = auth_from_headers()
    ok = save_post(sid, uid, bytes.fromhex(pid_hex))
    return jsonify({"ok": ok})


@app.route("/api/posts/<pid_hex>/save", methods=["DELETE"])
def api_unsave_post(pid_hex):
    uid, sid = auth_from_headers()
    ok = unsave_post(sid, uid, bytes.fromhex(pid_hex))
    return jsonify({"ok": ok})


@app.route("/api/saved_posts", methods=["GET"])
def api_saved_posts():
    uid, _ = auth_from_headers()
    with STATE_LOCK:
        pids = list(saved_posts.get(uid, set()))
    return jsonify({"post_ids": [p.hex() for p in pids]})


@app.route("/api/users/<username>", methods=["GET"])
def api_get_user(username):
    meta = get_user_metadata(get_uid(username))
    if meta is None:
        return jsonify({"error": "User does not exist"}), 404
    return jsonify(meta)


@app.route("/api/follow", methods=["POST"])
def api_follow():
    uid, sid = auth_from_headers()
    target_uid = get_uid(request.get_json(force=True)["username"])
    ok, err = follow(sid, uid, target_uid)
    if not ok:
        return jsonify({"error": err}), 400
    return jsonify({"ok": True})


@app.route("/api/unfollow", methods=["POST"])
def api_unfollow():
    uid, sid = auth_from_headers()
    target_uid = get_uid(request.get_json(force=True)["username"])
    ok, err = unfollow(sid, uid, target_uid)
    if not ok:
        return jsonify({"error": err}), 400
    return jsonify({"ok": True})


@app.route("/api/followed_boards/<board_owner>/<board_name>", methods=["POST"])
def api_follow_board(board_owner, board_name):
    uid, sid = auth_from_headers()
    bid = get_bid(get_uid(board_owner), board_name)
    ok = follow_board(sid, uid, bid)
    return jsonify({"ok": ok})


@app.route("/api/followed_boards/<board_owner>/<board_name>", methods=["DELETE"])
def api_unfollow_board(board_owner, board_name):
    uid, sid = auth_from_headers()
    bid = get_bid(get_uid(board_owner), board_name)
    ok = unfollow_board(sid, uid, bid)
    return jsonify({"ok": ok})


@app.route("/api/followed_boards", methods=["GET"])
def api_list_followed_boards():
    uid, _ = auth_from_headers()
    with STATE_LOCK:
        bids = list(followed_boards.get(uid, set()))
    boards_out = [dict(get_board_metadata(b), board_id=b.hex()) for b in bids]
    return jsonify({"boards": boards_out})


@app.route("/api/feed/next", methods=["POST"])
def api_feed_next():
    """Atomically pop the next feed item so two tabs can't both consume it."""
    uid, sid = auth_from_headers()
    pid, err = pop_feed_item(sid, uid)
    if err:
        return jsonify({"error": err}), 401
    if pid is None:
        return jsonify({"post_id": None})
    return jsonify({"post_id": pid.hex()})


@app.route("/api/feed", methods=["GET"])
def api_feed_peek():
    uid, sid = auth_from_headers()
    if not check_user_auth(uid, sid):
        return jsonify({"error": "Not authenticated"}), 401
    pids = peek_feed(sid, uid)
    return jsonify({"post_ids": [p.hex() for p in pids]})


@app.route("/api/search", methods=["GET"])
def api_search():
    text = request.args.get("q", "")
    n = int(request.args.get("n", 5))
    query = get_keywords(text)
    results = get_top_n_matches(query, top_n=n, metric="jaccard")
    return jsonify({"results": [{"post_id": pid.hex(), "score": score} for pid, score in results]})


if __name__ == "__main__":
    if os.path.exists(SAVE_PATH):
        load_save(SAVE_PATH)
    else:
        initialize_platform()
    try:
        # threaded=True so concurrent requests are actually possible to test
        # locking against; STATE_LOCK is what keeps that safe.
        app.run(host="127.0.0.1", port=8000, threaded=True)
    finally:
        save_platform()
