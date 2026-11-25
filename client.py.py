"""
client.py - CLI client for server.py.

Run the server first:
    python server.py

Then, in another terminal:
    pip install requests
    python client.py                      # talks to http://127.0.0.1:8000
    python client.py https://yourdomain.com   # talks to a remote HTTPS server

This holds no state of its own beyond the uid/sid it got back from login -
every read and write goes over HTTP to server.py, which is the only place
that touches the shared data and the only place that needs the lock.
"""

import sys
import time

import requests

BASE_URL = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8000"


class Session:
    def __init__(self):
        self.username = None
        self.uid_hex = None
        self.sid_hex = None

    def headers(self):
        return {"X-Uid": self.uid_hex or "", "X-Sid": self.sid_hex or ""}

    def logged_in(self):
        return self.sid_hex is not None


sess = Session()


def post(path, json=None, auth=True):
    headers = sess.headers() if auth else {}
    r = requests.post(f"{BASE_URL}{path}", json=json or {}, headers=headers)
    return r


def get(path, params=None, auth=True):
    headers = sess.headers() if auth else {}
    r = requests.get(f"{BASE_URL}{path}", params=params, headers=headers)
    return r


def put(path, json=None):
    r = requests.put(f"{BASE_URL}{path}", json=json or {}, headers=sess.headers())
    return r


def delete(path):
    r = requests.delete(f"{BASE_URL}{path}", headers=sess.headers())
    return r


def die_if_error(r):
    if r.status_code >= 400:
        try:
            print(f"Error: {r.json().get('error', r.text)}")
        except ValueError:
            print(f"Error: HTTP {r.status_code}")
        return True
    return False


def login_or_signup():
    choice = input("Login or Signup (L/S): ").strip().lower()
    if choice == "l":
        username = input("Enter username: ")
        password = input("Enter password: ")
        r = post("/api/login", {"username": username, "password": password}, auth=False)
    else:
        username = input("Enter username: ")
        name = input("Enter name: ")
        description = input("Enter description: ")
        password = input("Enter password: ")
        r = post("/api/signup", {"username": username, "name": name,
                                  "description": description, "password": password}, auth=False)
    if die_if_error(r):
        return False
    data = r.json()
    sess.username = username
    sess.uid_hex = data["uid"]
    sess.sid_hex = data["sid"]
    print(f"Logged in as {username}.")
    return True


def display_post(pid_hex):
    r = get(f"/api/posts/{pid_hex}")
    if die_if_error(r):
        return
    post_data = r.json()
    print(f"\nTitle: {post_data['title']}")
    print(f"Description: {post_data['description']}")
    print(f"Content: {post_data['content']}")
    print(f"Date Posted: {time.ctime(post_data['date_created'])}")
    print(f"Views: {post_data['views']}")


def menu():
    print(
        "\nETC Social\n\n"
        "New Board  ------->  (1)\n"
        "New Post   ------->  (2)\n"
        "View Board ------->  (3)\n"
        "View Saved Posts-->  (4)\n"
        "View User  ------->  (5)\n"
        "Edit Board access->  (6)\n"
        "Follow user ------>  (7)\n"
        "Unfollow user ---->  (8)\n"
        "Follow board ----->  (9)\n"
        "View followed boards (10)\n"
        "View feed  ------->  (11)\n"
        "Search posts ----->  (12)\n"
        "Quit       ------->  (0)\n"
    )
    try:
        return int(input("Enter action number: "))
    except ValueError:
        print("Invalid input")
        return -1


def collect_usernames(prompt_first, sentinel_is_empty=True):
    """Collect a list of usernames from stdin until the user signals done."""
    names = []
    while True:
        entry = input(prompt_first)
        if sentinel_is_empty and entry == "":
            break
        if not sentinel_is_empty and entry.lower() == "done":
            break
        names.append(entry)
        prompt_first = "Enter username, Enter to exit: " if sentinel_is_empty else "Enter username ('done' to finish): "
    return names


def action_new_board():
    board_name = input("Enter the board name: ")
    board_description = input("Enter the board description: ")
    is_whitelisted = input("Is the board whitelisted (Y/n): ").strip().lower() == "y"
    whitelist = []
    if is_whitelisted:
        print(f"(You, {sess.username}, are added automatically)")
        whitelist = [sess.username] + collect_usernames("Enter username to whitelist, Enter to exit: ")
    whitelist_uids = [get_uid_hex(u) for u in whitelist]
    r = post("/api/boards", {
        "board_name": board_name, "board_description": board_description,
        "is_whitelisted": is_whitelisted, "whitelist": whitelist_uids, "blacklist": [],
    })
    if not die_if_error(r):
        print("Board created.")


def get_uid_hex(username):
    import hashlib
    return hashlib.sha256(username.encode("utf-8")).digest().hex()


def action_new_post():
    board_name = input("Enter the board name: ")
    board_owner = input("Enter the board owner's username: ")
    post_name = input("Enter the post title: ")
    post_description = input("Enter the post description: ")
    post_content = input("Enter the post content: ")
    r = post("/api/posts", {
        "board_name": board_name, "board_owner": board_owner, "post_name": post_name,
        "post_description": post_description, "post_content": post_content,
    })
    if not die_if_error(r):
        print("Post created.")


def action_view_board():
    board_name = input("Enter the board name: ")
    creator_username = input("Enter the creator's username: ")
    r = get(f"/api/boards/{creator_username}/{board_name}")
    if die_if_error(r):
        return
    board = r.json()
    print(f"\nCreator: {board['creator_username']}")
    print(f"Board: {board['board_name']}")
    print(f"Description: {board['board_description']}\n")
    for pid_hex in board["post_ids"]:
        display_post(pid_hex)
        if input("Save this post? (Enter to continue, Y for yes): ").strip().lower() == "y":
            r2 = post(f"/api/posts/{pid_hex}/save")
            if not die_if_error(r2):
                print("Post saved!")


def action_view_saved_posts():
    r = get("/api/saved_posts")
    if die_if_error(r):
        return
    for pid_hex in r.json()["post_ids"]:
        display_post(pid_hex)


def action_view_user():
    username = input("Enter username: ")
    r = get(f"/api/users/{username}")
    if die_if_error(r):
        return
    u = r.json()
    print(f"\nUsername: {u['username']}\nName: {u['name']}\nBio: {u['description']}")


def action_edit_board_access():
    board_name = input("Enter the board name: ")
    is_whitelisted = input("Is the board whitelisted (Y/n): ").strip().lower() == "y"
    whitelist = []
    if is_whitelisted:
        whitelist = [sess.username] + collect_usernames("Enter username to whitelist, Enter to exit: ")
    is_blacklisted = input("Is the board blacklisted (Y/n): ").strip().lower() == "y"
    blacklist = []
    if is_blacklisted:
        blacklist = collect_usernames("Enter username to blacklist, Enter to exit: ")
    r = put(f"/api/boards/{sess.username}/{board_name}/access", {
        "is_whitelisted": is_whitelisted,
        "whitelist": [get_uid_hex(u) for u in whitelist],
        "blacklist": [get_uid_hex(u) for u in blacklist],
    })
    if not die_if_error(r):
        print("Board access updated.")


def action_follow():
    username = input("Enter username to follow: ")
    r = post("/api/follow", {"username": username})
    if not die_if_error(r):
        print(f"Now following {username}.")


def action_unfollow():
    username = input("Enter username to unfollow: ")
    r = post("/api/unfollow", {"username": username})
    if not die_if_error(r):
        print(f"Unfollowed {username}.")


def action_follow_board():
    board_name = input("Enter the board name: ")
    creator_username = input("Enter the creator's username: ")
    r = post(f"/api/followed_boards/{creator_username}/{board_name}")
    if not die_if_error(r):
        print("Board followed.")


def action_view_followed_boards():
    r = get("/api/followed_boards")
    if die_if_error(r):
        return
    for b in r.json()["boards"]:
        print(f"\n{b['board_name']} by {b['creator_username']} - {b['board_description']}")


def action_view_feed():
    while True:
        r = post("/api/feed/next")
        if die_if_error(r):
            return
        pid_hex = r.json()["post_id"]
        if pid_hex is None:
            print("End of feed")
            return
        display_post(pid_hex)
        if input("Press enter to view the next post, or 'q' to stop: ").strip().lower() == "q":
            return


def action_search():
    text = input("Enter search: ")
    n = input("Enter max number of results: ")
    try:
        n = int(n)
    except ValueError:
        print("Invalid number, defaulting to 5")
        n = 5
    r = get("/api/search", {"q": text, "n": n})
    if die_if_error(r):
        return
    results = r.json()["results"]
    if not results:
        print("No matches.")
    for res in results:
        display_post(res["post_id"])
        print(f"Similarity score: {res['score']:.3f}")


ACTIONS = {
    1: action_new_board,
    2: action_new_post,
    3: action_view_board,
    4: action_view_saved_posts,
    5: action_view_user,
    6: action_edit_board_access,
    7: action_follow,
    8: action_unfollow,
    9: action_follow_board,
    10: action_view_followed_boards,
    11: action_view_feed,
    12: action_search,
}


def main():
    print(f"Connecting to {BASE_URL}")
    while not login_or_signup():
        pass
    while True:
        action = menu()
        if action == 0:
            print("Goodbye.")
            return
        fn = ACTIONS.get(action)
        if fn is None:
            print("Invalid action")
            continue
        try:
            fn()
        except requests.exceptions.ConnectionError:
            print("Could not reach server.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nGoodbye.")
