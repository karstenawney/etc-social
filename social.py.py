# users
# uid : (username: str, name: str, description: str)

# set of admins
# uid: set[bytes]

# posts
# pid : (uid: bytes, bid: bytes, post_name: str, post_description: str, postcontent: str, date_created: int)

# views
# pid: views: int

# followers
# uid: followers: set[uid]

# following
# uid: following: set[uid]

# saved posts
# uid: set[pid]

# followed boards
# uid: set[bid]

# boards
# bid : (creator_uid: bytes, board_name: str, board_description: str, is_whitelisted: bool, whitelist: set[bytes], blacklist: set[bytes])

# posts by user
# uid : set[pid]

# posts by board
# bid : set[pid]

# active sessions
# uid : (sid, expiration_timestamp)

# accounts (encrypted)
# uid : passhash

# feed
# uid : list[pid]

# keywords
# pid : set[keyword: str]

# uid = hashlib.sha256(username.encode('utf-8')).digest()
# pid = bytes(x ^ y for x, y in zip(uid, hashlib.sha256(date_created.to_bytes(8, byteorder='big')))).digest()
# bid = bytes(x ^ y for x, y in zip(creator_uid, hashlib.sha256(board_name.encode('utf-8')))).digest()
# passhash = hashlib.sha256(password.encode('utf-8')).digest()

import hashlib
import time
import pickle
import os
import hmac
import secrets
import re

def get_uid(username):
    return hashlib.sha256(username.encode('utf-8')).digest()

def get_pid(uid, date_created):
    return bytes(x ^ y for x, y in zip(uid, hashlib.sha256(date_created.to_bytes(8, byteorder='big')).digest()))

def get_bid(creator_uid, board_name):
    return bytes(x ^ y for x, y in zip(creator_uid, hashlib.sha256(board_name.encode('utf-8')).digest()))

def get_passhash(password):
    return hashlib.sha256(password.encode('utf-8')).digest()

def initialize_platform():
    global users, admins, posts, views, followers, following, saved_posts, followed_boards, boards, user_posts, board_posts, sessions, accounts, feed, keywords
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
    global users, admins, posts, views, followers, following, saved_posts, followed_boards, boards, user_posts, board_posts, sessions, accounts, feed, keywords
    data = [users, admins, posts, views, followers, following, saved_posts, followed_boards, boards, user_posts, board_posts, sessions, accounts, feed, keywords]
    with open(f"save.pkl", "wb") as f: # {int(time.time())}
        pickle.dump(data, f)

def load_save(savename):
    global users, admins, posts, views, followers, following, saved_posts, followed_boards, boards, user_posts, board_posts, sessions, accounts, feed, keywords
    with open(savename, "rb") as f:
        data = pickle.load(f)
    users = data[0]
    admins = data[1]
    posts = data[2]
    views = data[3]
    followers = data[4]
    following = data[5]
    saved_posts = data[6]
    followed_boards = data[7]
    boards = data[8]
    user_posts = data[9]
    board_posts = data[10]
    sessions = data[11]
    accounts = data[12]
    feed = data[13]
    keywords = data[14]

def create_user(username, name, description, password):
    global users, followers, following, saved_posts, followed_boards, user_posts, accounts, feed
    uid = get_uid(username)
    if uid in users:
        print ("Error: Username exists")
    else:
        users[uid] = username, name, description
        followers[uid] = set()
        following[uid] = set()
        saved_posts[uid] = set()
        followed_boards[uid] = set()
        user_posts[uid] = set()
        passhash = get_passhash(password)
        accounts[uid] = passhash
        feed[uid] = []

def check_user_auth(uid, sid):
    global sessions
    if uid in sessions:
        if time.time() > sessions[uid][1]:
            del sessions[uid]
            return False
        try:
            valid = hmac.compare_digest(sessions[uid][0], sid)
        except TypeError:
            valid = False
        return valid
    return False

def deauth_user(uid):
    global sessions
    if uid in sessions:
        del sessions[uid]

def auth_user(uid, password):
    global sessions, accounts
    passhash = get_passhash(password)
    if uid in accounts and hmac.compare_digest(accounts[uid], passhash):
        sid = secrets.token_bytes(32)
        sessions[uid] = sid, int(time.time()) + 1800
        return sid
    return None

def create_board(sid, creator_uid, board_name, board_description, is_whitelisted, whitelist, blacklist):
    if check_user_auth(creator_uid, sid):
        global boards, board_posts
        bid = get_bid(creator_uid, board_name)
        if bid in boards:
            print ("Error: Board exists")
        else:
            boards[bid] = creator_uid, board_name, board_description, is_whitelisted, whitelist, blacklist
            board_posts[bid] = set()

def create_post(sid, uid, bid, post_name, post_description, post_content, date_created):
    if check_user_auth(uid, sid):
        global posts, boards, views, board_posts, user_posts, followers, feed, keywords
        pid = get_pid(uid, date_created)
        if pid in posts:
            print ("Error: Post exists")
        else:
            if bid not in boards:
                print ("Error: Board does not exist")
                return
            
            board = boards[bid]
            creator_uid, board_name, board_description, is_whitelisted, whitelist, blacklist = board
            
            # Check permissions using uid and correct dictionary indices
            if uid not in blacklist and (not is_whitelisted or uid in whitelist):
                posts[pid] = uid, bid, post_name, post_description, post_content, date_created
                views[pid] = 0
                board_posts[bid].add(pid)
                user_posts[uid].add(pid) # Fixed: changed bid to uid
                user_followers = followers[uid]
                for follower in user_followers:
                    feed[follower].append(pid)
                post_text = f"{post_name} {post_description} {post_content}".lower()
                keywords[pid] = get_keywords(post_text)
            else:
                print ("Error: User not allowed on board")

def get_keywords(post_text):
    post_text = re.sub(r"[^a-z\s]", "", post_text)
    prefixes = r"\b(un|re|in|im|il|ir|dis)"
    post_text = re.sub(prefixes, "", post_text)
    suffixes = r"(s|es|ed|ing|ly)\b"
    post_text = re.sub(suffixes, "", post_text)
    post_words = post_text.split()
    return set(post_words)

def view_post(pid):
    global posts, views
    title = posts[pid][2]
    desc = posts[pid][3]
    content = posts[pid][4]
    date = posts[pid][5]
    num_views = views[pid]
    print (f"Title: {title}")
    print (f"Description: {desc}")
    print (f"Content: {content}")
    print (f"Date Posted: {date}")
    print (f"Views: {num_views}")
    views[pid] += 1

def view_board_metadata(bid):
    creator_uid = boards[bid][0]
    board_name = boards[bid][1]
    board_description = boards[bid][2]
    creator_username = users[creator_uid][0]
    print (f"Creator's Username: {creator_username}")
    print (f"Board Name: {board_name}")
    print (f"Board Description: {board_description}")

def view_user_metadata(uid):
    if uid in users:
        username, name, description = users[uid]
        print (f"Username: {username}")
        print (f"Name: {name}")
        print (f"Bio: {description}")
    else:
        print ("User does not exist")

def follow(sid, follower_uid, following_uid):
    if check_user_auth(follower_uid, sid):
        global following, followers
        if following_uid in users:
            following[follower_uid].add(following_uid)
            followers[following_uid].add(follower_uid)
        else:
            print ("User does not exist")

def unfollow(sid, follower_uid, following_uid):
    if check_user_auth(follower_uid, sid):
        global following, followers
        if following_uid in users:
            following[follower_uid].discard(following_uid)
            followers[following_uid].discard(follower_uid)
        else:
            print ("User does not exist")

def login_user(username, password):
    uid = get_uid(username)
    sid = auth_user(uid, password)
    if sid == None:
        print("User auth failed")
    else:
        print(f"Your Session Identifier is: {sid}")
    return sid

def save_post(sid, uid, pid):
    if check_user_auth(uid, sid):
        global saved_posts
        if pid in posts:
            saved_posts[uid].add(pid)

def follow_board(sid, uid, bid):
    if check_user_auth(uid, sid):
        global followed_boards
        if bid in boards:
            followed_boards[uid].add(bid)

def update_board_access(sid, uid, bid, is_whitelisted, whitelist=None, blacklist=None):
    global boards
    if check_user_auth(uid, sid) and bid in boards and boards[bid][0] == uid:
        board = boards[bid]
        board_name = board[1]
        board_description = board[2]
        boards[bid] = uid, board_name, board_description, is_whitelisted, whitelist, blacklist

def get_top_n_matches(query, top_n=3, metric="overlap"):
    global keywords
    starttime = time.time_ns()
    scores = []

    for pid, keyword in keywords.items():
        intersection = len(keyword & query)

        if metric == "jaccard":
            union = len(keyword | query)
            score = intersection / union if union > 0 else 0.0
        else:
            score = intersection  # Absolute overlap count

        # Only keep posts that have at least 1 matching keyword
        if score > 0:
            scores.append((pid, score))

    # Sort descending by score
    scores.sort(key=lambda x: x[1], reverse=True)
    endtime = time.time_ns()
    print (f"Searched {len(keywords)} posts in {((endtime - starttime) / 1000000)} ms")
    input ("Press enter to see search results")
    return scores[:top_n]

def display_post(pid):
    creator_uid = posts[pid][0]
    bid = posts[pid][1]
    print ("User: ")
    view_user_metadata(creator_uid)
    print ("\nBoard: ")
    view_board_metadata(bid)
    print ("\nPost: ")
    view_post(pid)

def main():
    ls = input("Login or Signup (L/S): ").lower()
    if ls == "l":
        username = input("Enter username: ")
        password = input("Enter password: ")
        sid = login_user(username, password)
    else:
        username = input("Enter username: ")
        name = input("Enter name: ")
        description = input("Enter description: ")
        password = input("Enter password: ")
        create_user(username, name, description, password)
        sid = login_user(username, password)
    while True:
        input ("Press Enter to continue")
        os.system('cls' if os.name == 'nt' else 'clear')
        if not check_user_auth(get_uid(username), sid):
            username = input("Enter username: ")
            password = input("Enter password: ")
            sid = login_user(username, password)
        try:
            os.system('cls' if os.name == 'nt' else 'clear')
            print ("ETC Social\n\n" \
            "New Board  ------->  (1)\n" \
            "New Post   ------->  (2)\n" \
            "View Board ------->  (3)\n" \
            "View Saved Posts-->  (4)\n" \
            "View User  ------->  (5)\n" \
            "Edit Board access->  (6)\n" \
            "Follow user ------>  (7)\n" \
            "Unfollow user ---->  (8)\n" \
            "Follow board ----->  (9)\n" \
            "View followed boards (10)\n" \
            "View feed  ------->  (11)\n" \
            "Search posts ----->  (12)\n\n")
            action = int(input("Enter action number: "))
        except ValueError:
            print ("Invalid input")
            continue
        uid = get_uid(username)
        if action == 1: # New board
            board_name = input("Enter the board name: ")
            board_description = input("Enter the board description: ")
            is_whitelisted = input("Is the board whitelisted (Y/n): ").lower()
            is_whitelisted = is_whitelisted == "y"
            if is_whitelisted:
                entry = username
                whitelist = []
                while entry.lower() != "done":
                    whitelist.append(get_uid(entry))
                    entry = input("Enter username to whitelist: ")
                whitelist = set(whitelist)
            else:
                whitelist = set()
            create_board(sid, uid, board_name, board_description, is_whitelisted, whitelist, set())
        if action == 2: # New post
            board_name = input("Enter the board name: ")
            board_owner = input("Enter the board owner: ")
            post_name = input("Enter the post title: ")
            post_description = input("Enter the post description: ")
            post_content = input("Enter the post content: ")
            board_owner_uid = get_uid(board_owner)
            create_post(sid, uid, get_bid(board_owner_uid, board_name), post_name, post_description, post_content, int(time.time()))
        if action == 3: # View board
            board_name = input("Enter the board name: ")
            creator_username = input("Enter the creator's username: ")
            creator_uid = get_uid(creator_username)
            bid = get_bid(creator_uid, board_name)
            if bid in board_posts:
                pids = sorted(board_posts[bid], key=lambda pid: posts[pid][5])
                for pid in pids:
                    os.system('cls' if os.name == 'nt' else 'clear')
                    display_post(pid)
                    pin = input("Save this post? (Enter to continue, Y for yes): ")
                    if pin.lower() == "y":
                        save_post(sid, uid, pid)
                        print ("Post saved!")
            else:
                print ("Board Does not exist")
        if action == 4: # View saved posts
            saved = saved_posts[uid]
            for pid in saved:
                view_post(pid)
        if action == 5: # View user
            viewing_username = input("Enter username: ")
            viewing_uid = get_uid(viewing_username)
            view_user_metadata(viewing_uid)
        if action == 6: # Edit board access
            board_name = input("Enter the board name: ")
            bid = get_bid(uid, board_name)
            is_whitelisted = input("Is the board whitelisted (Y/n): ").lower()
            is_whitelisted = is_whitelisted == "y"
            if is_whitelisted:
                entry = username
                whitelist = []
                while entry.lower() != "":
                    whitelist.append(get_uid(entry))
                    entry = input("Enter username to whitelist, Enter to exit: ")
                whitelist = set(whitelist)
            else:
                whitelist = set()

            is_blacklisted = input("Is the board blacklisted (Y/n): ").lower()
            is_blacklisted = is_blacklisted == "y"
            if is_blacklisted:
                entry = "none"
                blacklist = []
                while entry.lower() != "":
                    if entry != "none":
                        blacklist.append(get_uid(entry))
                    entry = input("Enter username to blacklist, Enter to exit: ")
                blacklist = set(blacklist)
            else:
                blacklist = set()
            update_board_access(sid, uid, bid, is_whitelisted, whitelist, blacklist)
        if action == 7: # Follow user
            following_username = input("Enter username to follow: ")
            following_uid = get_uid(following_username)
            follow(sid, uid, following_uid)
        if action == 8: # Unfollow user
            following_username = input("Enter username to unfollow: ")
            following_uid = get_uid(following_username)
            unfollow(sid, uid, following_uid)
        if action == 9: # Follow board
            board_name = input("Enter the board name: ")
            creator_username = input("Enter the creator's username: ")
            creator_uid = get_uid(creator_username)
            bid = get_bid(creator_uid, board_name)
            follow_board(sid, uid, bid)
        if action == 10: # View Followed Boards
            for board in followed_boards[uid]:
                view_board_metadata(board)
        if action == 11: # View Feed
            user_feed = feed[uid]
            for pid in user_feed:
                os.system('cls' if os.name == 'nt' else 'clear')
                display_post(pid)
                input ("Press enter to view the next post: ")
                feed[uid] = feed[uid][1:]
            print ("End of feed")
        if action == 12: # Search
            text = input("Enter search: ")
            n = int(input("Enter number of max results: "))
            keyword_set = get_keywords(text)
            for i, keyword in enumerate(keyword_set):
                print (f"Keyword {i + 1}: {keyword}")
            input("Press enter to initiate search")
            results = get_top_n_matches(keyword_set, n, metric='jaccard')
            for result in results:
                os.system('cls' if os.name == 'nt' else 'clear')
                pid = result[0]
                score = result[1]
                display_post(pid)
                print (f"\nSimilarity Score: {score}\n")
                input ("Press enter to view the next post: ")
if __name__ == "__main__":
    if os.path.exists("save.pkl"):
        load_save("save.pkl")
    else:
        initialize_platform()
    try:
        main()
    except KeyboardInterrupt:
        save_platform()