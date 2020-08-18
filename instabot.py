#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from datetime import datetime

import atexit
import datetime
import itertools
import json
import logging
import os
import pickle
import random
import re
import signal
import time

import instaloader
import requests
from config42 import ConfigManager

import instabot_py
from instabot_py.default_config import DEFAULT_CONFIG
from instabot_py.persistence.manager import PersistenceManager


class CredsMissing(Exception):
    """ Raised when the Instagram credentials are missing"""
    message = "Instagram credentials are missing."

    def __str__(self):
        return CredsMissing.message


class InstaBot:
    """
    Instabot.py

    """

    url = "https://www.instagram.com/"
    url_tag = "https://www.instagram.com/explore/tags/%s/?__a=1"
    url_location = "https://www.instagram.com/explore/locations/%s/?__a=1"
    url_likes = "https://www.instagram.com/web/likes/%s/like/"
    url_unlike = "https://www.instagram.com/web/likes/%s/unlike/"
    url_comment = "https://www.instagram.com/web/comments/%s/add/"
    url_follow = "https://www.instagram.com/web/friendships/%s/follow/"
    url_unfollow = "https://www.instagram.com/web/friendships/%s/unfollow/"
    url_login = "https://www.instagram.com/accounts/login/ajax/"
    url_logout = "https://www.instagram.com/accounts/logout/"
    url_media_detail = "https://www.instagram.com/p/%s/?__a=1"
    url_media = "https://www.instagram.com/p/%s/"
    url_user_detail = "https://www.instagram.com/%s/"
    api_user_detail = "https://i.instagram.com/api/v1/users/%s/info/"
    url_accounts_login = 'https://www.instagram.com/accounts/login/'

    def __init__(self, config=None, **kwargs):
        self.logger = logging.getLogger(self.__class__.__name__)
        if not config:
            self.config = ConfigManager(defaults=DEFAULT_CONFIG)
            self.config.set_many(kwargs)
        else:
            self.config = config

        self.logger_mode = 'DEBUG' if self.config.get('debug') else 'INFO'
        self.logger.setLevel(self.logger_mode)

        _login = self.config.get('login')
        _password = self.config.get('password')
        if not _login or _login == 'YOUR_USERNAME' or \
                not _password or _password == 'YOUR_PASSWORD':
            raise CredsMissing()

        _database = self.config.get('database')
        self.persistence = PersistenceManager(_database)
        self.logger.debug(f"Init SQL database {_database['connection_string']}")
        self.persistence.bot = self
        self.session_file = self.config.get('session_file')
        # log_mod 0 to console, 1 to file
        self.log_mod = self.config.get('log_mod')
        self.user_agent = self.config.get('user_agent')
        if not self.user_agent:
            self.user_agent = random.sample(self.config.get('list_of_ua'), 1)[0]
        self.bot_start = datetime.datetime.now()

        # Time settings
        self.start_day = datetime.datetime.today().day
        self.start_at_h = self.config.get('start_at_h')
        self.start_at_m = self.config.get('start_at_m')
        self.end_at_h = self.config.get('end_at_h')
        self.end_at_m = self.config.get('end_at_m')
        _st = datetime.datetime(1, 1, 1, self.start_at_h, self.start_at_m, 0)
        _end = datetime.datetime(1, 1, 1, self.end_at_h, self.end_at_m, 59)
        _delta = abs(int((_end - _st).total_seconds())) + 1
        self.time_in_run = _delta
        self.window_check_every = self.config.get('window_check_every')

        # Common settings
        self.instaloader = instaloader.Instaloader()
        # Default list of tag
        self.tag_list = self.config.get('tag_list')
        # Get random tag from a tag_list and like (1 to N) times
        self.max_like_for_one_tag = self.config.get('max_like_for_one_tag')
        # Default keywords
        self.keywords = self.config.get('keywords')
        self.user_blacklist = self.config.get('user_blacklist')
        self.tag_blacklist = self.config.get('tag_blacklist')
        self.unfollow_whitelist = self.config.get('unfollow_whitelist')
        # Not implemented yet
        self.unwanted_username_list = self.config.get('unwanted_username_list')

        # Like
        self.like_per_run = int(self.config.get('like_per_run'))
        if self.like_per_run > 0:
            self.like_delay = self.time_in_run / self.like_per_run
        # Don't like if media have less than n likes
        self.media_min_like = self.config.get('media_min_like')
        # Don't like if media have more than N likes
        self.media_max_like = self.config.get('media_max_like')

        # Unlike
        self.time_till_unlike = self.config.get('time_till_unlike')
        self.unlike_per_run = int(self.config.get('unlike_per_run'))
        if self.unlike_per_run > 0:
            self.unlike_delay = self.time_in_run / self.unlike_per_run

        # Follow
        self.follow_attempts = self.config.get('follow_attempts')
        self.follow_time = self.config.get('follow_time')
        self.follow_per_run = int(self.config.get('follow_per_run'))
        if self.follow_per_run > 0:
            self.follow_delay = self.time_in_run / self.follow_per_run
        # Don't follow if user have less than N followers
        self.user_min_follow = self.config.get('user_min_follow')
        # Don't follow if user have more than N followers
        self.user_max_follow = self.config.get('user_max_follow')

        # Unfollow
        self.unfollow_per_run = int(self.config.get('unfollow_per_run'))
        if self.unfollow_per_run > 0:
            self.unfollow_delay = self.time_in_run / self.unfollow_per_run
        # ?
        self.unfollow_break_min = self.config.get("unfollow_break_min")
        # ?
        self.unfollow_break_max = self.config.get("unfollow_break_max")
        self.unfollow_everyone = self.str2bool(
            self.config.get('unfollow_everyone')
        )
        self.unfollow_inactive = self.str2bool(
            self.config.get('unfollow_inactive')
        )
        self.unfollow_not_following = self.str2bool(
            self.config.get('unfollow_not_following')
        )
        self.unfollow_probably_fake = self.str2bool(
            self.config.get('unfollow_probably_fake')
        )
        self.unfollow_recent_feed = self.str2bool(
            self.config.get('unfollow_recent_feed')
        )
        self.unfollow_selebgram = self.str2bool(
            self.config.get('unfollow_selebgram')
        )
        # Not implemented yet
        self.unfollow_from_feed = False

        # Comment
        self.comments_per_run = int(self.config.get('comments_per_run'))
        if self.comments_per_run > 0:
            self.comments_delay = self.time_in_run / self.comments_per_run
        self.comment_list = self.config.get('comment_list')

        # Like your follower's medias
        self.like_followers_per_run = self.config.get('like_followers_per_run')
        if self.like_followers_per_run > 0:
            self.like_followers_delay = \
                self.time_in_run / self.like_followers_per_run

        # Proxy settings
        self.s = requests.Session()
        self.c = requests.Session()
        self.proxies = self.config.get('proxies')
        if self.proxies:
            self.s.proxies = {'http': self.proxies.get('http_proxy'),
                              'https': self.proxies.get('https_proxy')}
            self.c.proxies = {'http': self.proxies.get('http_proxy'),
                              'https': self.proxies.get('https_proxy')}

        # Action counters
        self.like_counter = 0
        self.like_followers_counter = 0
        self.unlike_counter = 0
        self.follow_counter = 0
        self.unfollow_counter = 0
        self.comments_counter = 0

        # Other variables
        self.user_login = _login
        self.user_password = _password
        self.user_id = 0
        self.login_status = False
        # Should be refactored
        self.error_400 = 0
        self.error_400_to_ban = self.config.get('error_400_to_ban')
        self.ban_sleep_time = self.config.get('ban_sleep_time')
        self.next_iteration = {
            "Like": 0,
            "Unlike": 0,
            "Follow": 0,
            "Unfollow": 0,
            "Comments": 0,
            "Populate": 0,
        }

        # Login into Instagram
        now_time = datetime.datetime.now()
        self.logger.info(f"Instabot v{instabot_py.__version__} started at "
                         f"{now_time.strftime('%Y-%b-%d %H:%M:%S')}")
        self.logger.debug(f"User agent '{self.user_agent}' is used")
        self.prog_run = True
        self.login()
        # Not implemented yet
        # self.populate_user_blacklist()
        # Need to check this part later
        self.csrftoken = ''
        signal.signal(signal.SIGINT, self.cleanup)
        signal.signal(signal.SIGTERM, self.cleanup)
        atexit.register(self.cleanup)

    def url_user(self, username):
        return self.url_user_detail % username

    def get_user_id_by_username(self, user_name):
        url_info = self.url_user_detail % user_name
        try:
            info = self.s.get(url_info)
            json_info = json.loads(re.search(
                "window._sharedData = (.*?);</script>", info.text,
                re.DOTALL).group(1))
            id_user = json_info['entry_data']['ProfilePage'][0]['graphql'][
                'user']['id']
            return id_user
        except:
            self.logger.warning(f"Could not retrieve information about user "
                                f"{user_name}, url: {url_info}. Status code: "
                                f"{info.status_code}")
            return

    def populate_user_blacklist(self):
        for user in self.user_blacklist:
            user_id_url = self.url_user_detail % (user)
            info = self.s.get(user_id_url)

            # prevent error if 'Account of user was deleted or link is invalid
            from json import JSONDecodeError

            try:
                all_data = json.loads(
                    re.search(
                        "window._sharedData = (.*?);</script>", info.text, re.DOTALL
                    ).group(1)
                )
            except JSONDecodeError as e:
                self.logger.info(
                    f"Account of user {user} was deleted or link is " "invalid"
                )
            else:
                # prevent exception if user have no media
                id_user = all_data["entry_data"]["ProfilePage"][0]["graphql"]["user"][
                    "id"
                ]
                # Update the user_name with the user_id
                self.user_blacklist[user] = id_user
                self.logger.info(f"Blacklisted user {user} added with ID: {id_user}")
                time.sleep(5 * random.random())

    def login(self):
        successful_login = False
        self.s.headers.update(
            {
                "Accept": "*/*",
                "Accept-Language": self.config.get('accept_language'),
                "Accept-Encoding": "gzip, deflate, br",
                "Connection": "keep-alive",
                "Host": "www.instagram.com",
                "Origin": "https://www.instagram.com",
                "Referer": "https://www.instagram.com/",
                "User-Agent": self.user_agent,
                "X-Instagram-AJAX": "1",
                "Content-Type": "application/x-www-form-urlencoded",
                "X-Requested-With": "XMLHttpRequest",
            }
        )

        if self.session_file and os.path.isfile(self.session_file):
            self.logger.info(f"Found session file {self.session_file}")
            successful_login = True
            with open(self.session_file, 'rb') as i:
                cookies = pickle.load(i)
                self.s.cookies.update(cookies)
        else:
            self.logger.info(f"Trying to login as {self.user_login}...")
            _time = int(datetime.datetime.now().timestamp())
            login_post = {
                'username': self.user_login,
                # TODO: add password encription according to AES-GCM
                'enc_password': f'#PWD_INSTAGRAM_BROWSER:0:{_time}:{self.user_password}',
                # <-- note the '0' - that means we want to use plain passwords
                'queryParams': {},
                'optIntoOneTap': 'false'
            }

            try:
                r = self.s.get(self.url_accounts_login)
                csrf_token = re.findall(r"csrf_token\":\"(.*?)\"", r.text)[0]
                login = self.s.post(
                    self.url_login,
                    data=login_post,
                    headers={
                        "user-agent": "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3865.120 Safari/537.36",
                        "x-requested-with": "XMLHttpRequest",
                        "referer": "https://www.instagram.com/accounts/login/",
                        "x-csrftoken": csrf_token
                    }
                                    )
            except Exception as exc:
                self.logger.exception(exc)
                return
            login_response = login.json()
            try:
                self.csrftoken = login.cookies['csrftoken']
                self.s.headers.update({"X-CSRFToken": self.csrftoken})
            except Exception as exc:
                self.logger.warning("Something wrong with the login")
                self.logger.debug(login.text)
                self.logger.exception(exc)

            if login_response.get('errors'):
                self.logger.error(f"Something is wrong with Instagram: "
                                  f"{login_response['errors']['error']}. Please"
                                  f"try to login later.")

            elif login_response.get('message') == 'checkpoint_required':
                try:
                    if 'instagram.com' in login_response['checkpoint_url']:
                        challenge_url = login_response['checkpoint_url']
                    else:
                        challenge_url = "https://instagram.com" + \
                                        login_response['checkpoint_url']
                    self.logger.info(f"Challenge is required at "
                                     f"{challenge_url}")
                    with self.s as clg:
                        clg.headers.update(
                            {
                                "Accept": "*/*",
                                "Accept-Language":
                                    self.config.get('accept_language'),
                                "Accept-Encoding": "gzip, deflate, br",
                                "Connection": "keep-alive",
                                "Host": "www.instagram.com",
                                "Origin": "https://www.instagram.com",
                                "User-Agent": self.user_agent,
                                "X-Instagram-AJAX": "1",
                                "Content-Type":
                                    "application/x-www-form-urlencoded",
                                "x-requested-with": "XMLHttpRequest",
                            }
                        )
                        # Get challenge page
                        challenge_request_explore = clg.get(challenge_url)

                        # Get CSRF Token from challenge page
                        challenge_csrf_token = re.search(
                            '(?<="csrf_token":")\w+',
                            challenge_request_explore.text).group(0)
                        # Get Rollout Hash from challenge page
                        rollout_hash = re.search(
                            '(?<="rollout_hash":")\w+',
                            challenge_request_explore.text).group(0)

                        # Ask for option 1 from challenge, which is usually
                        # Email or Phone
                        challenge_post = {"choice": 1}

                        # Update headers for challenge submit page
                        clg.headers.update(
                            {"X-CSRFToken": challenge_csrf_token})
                        clg.headers.update({"Referer": challenge_url})

                        # Request Instagram to send a code
                        challenge_request_code = clg.post(
                            challenge_url, data=challenge_post,
                            allow_redirects=True)

                        # User should receive a code soon, ask for it
                        challenge_userinput_code = input(
                            "Challenge is required.\n\nEnter the code which has"
                            " just been sent to your mail/phone: ")
                        challenge_security_post = {
                            "security_code": challenge_userinput_code
                        }

                        complete_challenge = clg.post(
                            challenge_url,
                            data=challenge_security_post,
                            allow_redirects=True,
                        )
                        if complete_challenge.status_code != 200:
                            self.logger.info("Entered code is not correct, "
                                             "Please try again later")
                            return
                        self.csrftoken = complete_challenge.cookies['csrftoken']
                        self.s.headers.update(
                            {"X-CSRFToken": self.csrftoken,
                             "X-Instagram-AJAX": "1"}
                        )
                        successful_login = complete_challenge.status_code == 200

                except Exception as err:
                    self.logger.debug(f"Login failed. Response: \n\n"
                                      f"{login.text} {err}")
                    return False
            elif login_response.get('authenticated') is False:
                self.logger.error(f"Could not login into Instagram with user "
                                  f"{self.user_login}. Make sure you are using"
                                  f" correct login and/or password.")
                return
            else:
                rollout_hash = re.search('(?<="rollout_hash":")\\w+',
                                         r.text).group(0)
                self.s.headers.update({"X-Instagram-AJAX": rollout_hash})
                successful_login = True
            # ig_vw=1536; ig_pr=1.25; ig_vh=772; ig_or=landscape-primary;
            self.s.cookies['csrftoken'] = self.csrftoken
            self.s.cookies['ig_vw'] = '1536'
            self.s.cookies['ig_pr'] = '1.25'
            self.s.cookies['ig_vh'] = '772'
            self.s.cookies['ig_or'] = 'landscape-primary'
            time.sleep(random.gauss(7, 2))

        if successful_login:
            try:
                r = self.s.get("https://www.instagram.com/")
                self.csrftoken = re.search('(?<="csrf_token":")\\w+',
                                           r.text).group(0)
                self.s.cookies['csrftoken'] = self.csrftoken
                self.s.headers.update({"X-CSRFToken": self.csrftoken})
                finder = r.text.find(self.user_login)
                if finder != -1:
                    self.login_status = True
                    self.logger.info(f"{self.user_login} has logged in "
                                     f"successfully!")
                    if self.session_file:
                        self.logger.info(f"Saving cookies to the session file "
                                         f"{self.session_file}")
                        with open(self.session_file, "wb") as output:
                            pickle.dump(self.s.cookies, output,
                                        pickle.DEFAULT_PROTOCOL)
                    # we need to wait between 3 to 9 seconds just after login
                    time.sleep(random.gauss(7, 2))
                else:
                    self.login_status = False
                    self.logger.error("Login error! Check your login data!")
                    if self.session_file and os.path.isfile(self.session_file):
                        self.remove_spoiled_session_file(self.session_file)
                    self.prog_run = False
            except Exception as exc:
                self.logger.exception(exc)
                return
        else:
            self.logger.error(f"Could not login to Instagram with user "
                              f"{self.user_login}")
            return

    def logout(self):
        now_time = datetime.datetime.now()
        work_time = now_time - self.bot_start
        self.logger.info(f"Bot has been working for {work_time}. Logging out "
                         f"from an Instagram ...")
        try:
            _ = self.s.post(self.url_logout,
                            data={"csrfmiddlewaretoken": self.csrftoken})
            self.logger.info("Logout has been successfully performed")
            self.login_status = False
            if self.session_file and os.path.isfile(self.session_file):
                self.remove_spoiled_session_file(self.session_file)
            exit(0)
        except Exception as exc:
            logging.error("Logout error!")
            logging.exception(exc)

    def cleanup(self, *_):
        if self.login_status and self.session_file is None:
            self.logout()
        self.prog_run = False

    def notify_about_settings(self):
        cmt = f"COMMENT medias every {self.sec_to_time(self.comments_delay)}\n"\
            if self.comments_per_run else ''
        lk = f"LIKE medias every {self.sec_to_time(self.like_delay)}\n" \
            if self.like_per_run else ''
        ulk = f"UNLIKE medias every {self.sec_to_time(self.unlike_delay)}\n" \
            if self.unlike_per_run else ''
        fw = f"FOLLOW users every {self.sec_to_time(self.follow_delay)}\n" \
            if self.follow_per_run else ''
        ufw = f"UNFOLLOW users every {self.sec_to_time(self.unfollow_delay)}\n"\
            if self.unfollow_per_run else ''

        message = f"""
+++++++++++++++++++++++++++++++++++++++++++++++
According to the configuration this bot will:
{lk}{ulk}{fw}{ufw}{cmt}+++++++++++++++++++++++++++++++++++++++++++++++"""
        self.logger.info(message)
        return

    def get_media_id_by_tag(self, tag):
        """ Get media ID set, by your hashtag or location """
        medias = None
        if tag.startswith('l:'):
            l_tag = tag.replace('l:', '')
            self.logger.debug(f"Getting media by location: {l_tag}")
            url_tag = self.url_location % l_tag
        else:
            self.logger.debug(f"Getting media by tag: {tag}")
            url_tag = self.url_tag % tag

        r = self.s.get(url_tag)
        if r.status_code == 200:
            if tag.startswith('l:'):
                try:
                    all_data = json.loads(r.text)
                    medias = list(all_data['graphql']['location'][
                                      'edge_location_to_media']['edges'])
                except Exception as exc:
                    self.logger.exception(exc)
            else:
                try:
                    all_data = json.loads(r.text)
                    medias = list(all_data['graphql']['hashtag'][
                                      'edge_hashtag_to_media']['edges'])
                except Exception as exc:
                    self.logger.exception(exc)
        else:
            self.logger.fatal(f"Could not find tag {tag} in Instagram. Please "
                              f"verify your configuration!")
            exit(1)

        return medias

    def get_medias(self):
        """ Get medias by random tag defined in configuration """
        while True:
            # we need to wait between 3 to 8 seconds before we retrieve medias
            time.sleep(random.gauss(6, 1.5))
            tag = random.choice(self.tag_list)
            medias_raw = self.get_media_id_by_tag(tag)
            self.logger.debug(f"Retrieved {len(medias_raw)} medias")
            max_tag_like_count = random.randint(1, self.max_like_for_one_tag)
            medias = self.remove_already_liked_medias(medias_raw)[
                     :max_tag_like_count]
            self.logger.debug(f"Selected {len(medias)} medias to process. "
                              f"Increase max_like_for_one_tag value for more "
                              f"processing medias")
            if medias:
                break
        # we need to wait between 3 to 8 seconds after we retrieved medias
        time.sleep(random.gauss(6, 1.5))
        return medias

    def get_media_url(self, media_id=None, shortcode=None):
        """ Get Media Code or Full Url from Media ID """
        if shortcode:
            return self.url_media % shortcode
        elif media_id:
            media_id = int(media_id)
            alphabet = ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz01"
                        "23456789-_")
            shortened_id = ''
            while media_id > 0:
                media_id, idx = divmod(media_id, 64)
                shortened_id = alphabet[idx] + shortened_id

            return self.url_media % shortened_id

    def get_username_by_user_id(self, user_id):
        try:
            profile = instaloader.Profile.from_id(self.instaloader.context,
                                                  user_id)
            return profile.username

        except Exception as exc:
            logging.exception(exc)

    def verify_media(self, media):
        # verify media_min_like requirements
        like_count = media['node']['edge_liked_by']['count']
        if self.media_min_like and like_count < self.media_min_like:
            self.logger.debug(f"Will not like this media: number of likes "
                              f"{like_count} does not meet media_min_like "
                              f"requirements")
            return False

        # verify media_max_like requirements
        if self.media_max_like and like_count > self.media_max_like:
            self.logger.debug(f"Will not like this media: number of likes "
                              f"{like_count} does not meet media_max_like "
                              f"requirements")
            return False

        # verify blacklisted tags
        edges = media['node']['edge_media_to_caption']['edges']
        if edges:
            caption = edges[0]['node']['text'].encode('ascii', errors='ignore')
            tag_blacklist = set(self.tag_blacklist)
            tags = {tag.decode('ASCII').strip('#').lower()
                    for tag in caption.split()
                    if (tag.decode('ASCII')).startswith('#')}
            matching_tags = tags.intersection(tag_blacklist)
            if matching_tags:
                self.logger.debug(f"Will not like this media: it has "
                                  f"blacklisted tag(s): "
                                  f"{', '.join(matching_tags)}")
                return False

        # verify blacklisted users
        for username, user_id in self.user_blacklist.items():
            if media['node']['owner']['id'] == user_id:
                self.logger.debug(f"Will not like this media: it is owned by "
                                  f"blacklisted user: {username}")
                return False

        # verify if it is your media
        if media['node']['owner']['id'] == self.user_id:
            self.logger.debug("Will not like this media: it is your media")
            return False
        return True

    def like(self, media_id, media_url):
        """ Send http request to view media by ID and then like it """
        # we are GETting a media first
        try:
            self.s.get(self.url_likes % media_id)
        except Exception as exc:
            logging.exception(exc)
            return False
        # we need to wait between 2 to 8 seconds before we like a media
        time.sleep(random.gauss(6, 1.5))
        try:
            resp = self.s.post(self.url_likes % media_id)
        except Exception as exc:
            logging.exception(exc)
            return False

        if resp.status_code == 200:
            self.persistence.insert_media(media_id=media_id, status="200")
            return True
        elif resp.status_code == 400 and 'Action Blocked' in str(resp.text):
            self.logger.info(f"Could not like media: id: {media_id}, url: "
                             f"{media_url}, status code: {resp.status_code}. "
                             f"Reason: {resp.text}")
            self.logger.fatal("Your like action has just been banned by "
                              "Instagram. Exiting from a program... You can "
                              "start your bot again if you disable like action "
                              "in your configuration: set 'like_per_run: 0'")
            self.logout()
        else:
            self.persistence.insert_media(media_id=media_id,
                                          status=str(resp.status_code))
            self.logger.info(f"Could not like media: id: {media_id}, "
                             f"url: {media_url}, "
                             f"status code: {resp.status_code}. "
                             f"Reason: {resp.text}")
            return False

    def unlike(self, media_id, media_url):
        """ Send http request to unlike media by ID """
        try:
            self.s.get(self.url_unlike % media_id)
        except Exception as exc:
            logging.exception(exc)
            return False
        # we need to wait between 2 to 8 seconds before we unlike a media
        time.sleep(random.gauss(6, 1.5))
        try:
            resp = self.s.post(self.url_unlike % media_id)
        except Exception as exc:
            logging.exception(exc)
            return False

        if resp.status_code == 200:
            self.persistence.update_media_complete(media_id)
            return True
        elif resp.status_code == 400 and resp.text == 'missing media':
            self.persistence.update_media_complete(media_id)
            self.logger.info(
                f"Could not unlike media: id: {media_id}, url: {media_url}. It "
                f"seems this media does not exist anymore.")
            return False
        elif resp.status_code == 400 and 'Action Blocked' in str(resp.text):
            self.logger.warning(
                f"Could not unlike media: id: {media_id}, url: {media_url}, "
                f"status code: {resp.status_code}. Reason: {resp.text}")
            self.logger.fatal(
                "Your unlike action has just been banned by Instagram. Exiting "
                "from a program... You can start your bot again if you disable"
                " unlike action in your configuration: set 'unlike_per_run: 0'")
            self.logout()
        else:
            self.logger.warning(
                f"Could not unlike media: id: {media_id}, url: {media_url}, "
                f"status code: {resp.status_code}. Reason: {resp.text}")
        return False

    def comment(self, media_id, comment_text):
        """ Send http request to comment endpoint """
        self.logger.info(f"Trying to comment {media_id}, url: "
                         f"{self.get_media_url(media_id)}")
        url_comment = self.url_comment % media_id
        media_url = self.get_media_url(media_id)

        resp = self.s.post(url_comment, data={'comment_text': comment_text})
        if resp.status_code == 200:
            self.comments_counter += 1
            self.logger.info(
                f"Comment #{self.comments_counter}: '{comment_text}' on media "
                f"{media_id}, url: {media_url}")
            return True
        elif resp.status_code == 400 and 'Action Blocked' in str(resp.text):
            self.logger.warning(
                f"Could not comment media: id: {media_id}, url: {media_url}, "
                f"status code: {resp.status_code}. Reason: {resp.text}")
            self.logger.fatal(
                "Your comment action has just been blocked by Instagram. "
                "Exiting from a program... You can start your bot again if you "
                "disable comment action in your configuration: set "
                "'comment_per_run: 0'")
            self.logout()
        else:
            self.logger.warning(
                f"Could not comment media: id: {media_id}, url: {media_url}, "
                f"status code: {resp.status_code}. Reason: {resp.text}")
        return False

    def follow(self, user_id, username=None):
        """ Send http request to follow endpoint """
        if self.login_status:
            url_follow = self.url_follow % user_id
            if not username:
                username = self.get_username_by_user_id(user_id=user_id)

            resp = self.s.post(url_follow)
            if resp.status_code == 200:
                self.follow_counter += 1
                self.logger.info(
                    f"Followed user #{self.follow_counter}: username: "
                    f"{username}, url: {self.url_user(username)}")
                self.persistence.insert_username(user_id=user_id,
                                                 username=username)
                return resp
            elif resp.status_code == 400 and 'Action Blocked' in str(resp.text):
                self.logger.warning(
                    f"Could not follow user: username: {username}, url: "
                    f"{self.url_user(username)}, status code: "
                    f"{resp.status_code}. Reason: {resp.text}")
                self.logger.fatal(
                    "Your follow action has just been blocked by Instagram. "
                    "Exiting from a program... You can start your bot again if"
                    " you disable follow action in your configuration: set "
                    "'follow_per_run: 0'")
                self.logout()
            else:
                self.logger.warning(
                    f"Could not follow user: username: {username}, url: "
                    f"{self.url_user(username)}, status code: "
                    f"{resp.status_code}. Reason: {resp.text}")
        return False

    def unfollow(self, user_id, username=None):
        """ Send http request to unfollow endpoint"""
        resp = self.s.post(self.url_unfollow % user_id)
        if resp.status_code == 200:
            self.unfollow_counter += 1
            self.persistence.insert_unfollow_count(user_id=user_id)
            self.logger.info(
                f"Unfollowed user #{self.unfollow_counter}: username: "
                f"{username}, url: {self.url_user(username)}")
            return True
        elif resp.status_code == 400 and 'Action Blocked' in str(resp.text):
            self.logger.warning(
                f"Could not unfollow user: username: {username}, url: "
                f"{self.url_user(username)}, status code: "
                f"{resp.status_code}. Reason: {resp.text}")
            self.logger.fatal(
                "Your unfollow action has just been blocked by Instagram. "
                "Exiting from a program... You can start your bot again if"
                " you disable unfollow action in your configuration: set "
                "'unfollow_per_run: 0'")
            self.logout()
        else:
            self.logger.warning(
                f"Could not unfollow user: username: {username}, url: "
                f"{self.url_user(username)}, status code: "
                f"{resp.status_code}. Reason: {resp.text}")
        return False

    # Backwards Compatibility for old example.py files
    def auto_mod(self):
        self.mainloop()

    def new_auto_mod(self):
        self.mainloop()

    def run_during_time_window(self):
        now = datetime.datetime.now()
        # distance between start time and now
        dns = self.time_dist(
            datetime.time(self.start_at_h, self.start_at_m), now.time()
        )
        # distance between end time and now
        dne = self.time_dist(
            datetime.time(self.end_at_h, self.end_at_m), now.time()
        )
        if not ((dns == 0 or dne < dns) and dne != 0):
            self.logger.info(f"Now it's time to rest for the bot according to "
                             f"the 'start_at_h', 'start_at_h', 'end_at_h' and "
                             f"'end_at_m' settings. Pause for "
                             f"{self.window_check_every} seconds")
            time.sleep(self.window_check_every)
            return False
        else:
            return True

    def loop_controller(self):
        # 400 errors
        if self.error_400 >= self.error_400_to_ban:
            self.logger.info(
                f"Bot has received {self.error_400} HTTP_400_Error(s). It seems"
                f" you're banned! Pause for {self.ban_sleep_time} seconds")
            time.sleep(self.generate_time(self.ban_sleep_time))
            self.error_400 = 0

        # exceed counters, program halt
        current_day = datetime.datetime.today().day
        if self.start_day == current_day:
            if self.like_counter > self.like_per_run \
                    and self.unlike_counter > self.unlike_per_run \
                    and self.follow_counter > self.follow_per_run \
                    and self.unfollow_counter > self.unfollow_per_run \
                    and self.comments_counter > self.comments_per_run:
                self.prog_run = False

            if self.iteration_ready('follow') \
                    or self.iteration_ready('unfollow') \
                    or self.iteration_ready('like') \
                    or self.iteration_ready('unlike') \
                    or self.iteration_ready('comments'):
                return True
            else:
                time.sleep(1)
                return False
        else:
            self.start_day = current_day
            self.like_counter, self.unlike_counter, self.follow_counter, \
                self.unfollow_counter, self.comments_counter = 0, 0, 0, 0, 0

    def mainloop(self):
        medias = []
        while self.prog_run and self.login_status:
            if not self.run_during_time_window():
                continue
            if not self.loop_controller():
                continue
            if not medias:
                medias = self.get_medias()

            media = medias.pop()
            self.new_auto_mod_like(media)
            self.new_auto_mod_unlike()

            if self.iteration_ready('follow') and self.follow_per_run and media:
                self.init_next_iteration('follow')
                while self.follow_attempts > 0:
                    if not self.new_auto_mod_follow(media):
                        time.sleep(5)
                        if not medias:
                            medias = self.get_medias()
                        media = medias.pop()
                        self.follow_attempts -= 1
                    else:
                        self.follow_attempts = self.config.get(
                            'follow_attempts')
                        break
                else:
                    self.follow_attempts = self.config.get('follow_attempts')
                    self.logger.debug(f"Could not find user to follow in "
                                      f"{self.follow_attempts} attempts. If you"
                                      f" want to increase this number, change"
                                      f" 'follow_attempts' value")

            self.new_auto_mod_unfollow()
            self.new_auto_mod_comments(media)
            self.like_followers_last_media()

        self.logger.info("Exit from a program. See you later.")

    def remove_already_liked_medias(self, medias):
        return [media for media in medias if not
                self.persistence.check_already_liked(
                    media_id=media['node']['id'])]

    def remove_spoiled_session_file(self, session_file):
        try:
            os.remove(session_file)
            self.logger.info(f"{session_file} has been successfully deleted")
        except:
            self.logger.info(f"Could not delete your session file "
                             f"{session_file}. Please delete it manually")

    def new_auto_mod_like(self, media):
        if self.iteration_ready('like') and media:
            self.init_next_iteration('like')
            media_id = media['node']['id']
            media_url = self.get_media_url(media_id)
            self.logger.debug(f"Trying to like media #{self.like_counter + 1}: "
                              f"id: {media_id}, url: {media_url}")
            if self.verify_media(media):
                if self.like(media_id, media_url):
                    self.error_400 = 0
                    self.like_counter += 1
                    self.logger.info(f"Liked media #{self.like_counter}: "
                                     f"id: {media_id}, url: {media_url}")
                    return True
        return False

    def like_followers_last_media(self):
        if self.iteration_ready('like_followers'):
            self.init_next_iteration('like_followers')
            follower = self.persistence.get_follower_to_like_random()
            if not follower:
                self.logger.debug("You don't have followers to like their "
                                  "medias")
                return False
            url_tag = self.url_user_detail % follower.username
            try:
                r = self.s.get(url_tag)
                if r.status_code != 200:
                    return False
                raw_data = re.search("window._sharedData = (.*?);</script>",
                                     r.text, re.DOTALL).group(1)
                media_id = json.loads(raw_data)['entry_data']['ProfilePage'][0][
                    'graphql']['user']['edge_owner_to_timeline_media'][
                    'edges'][0]['node']['id']
                self.logger.debug(f"Trying to like media of your old follower "
                                  f"#{self.like_followers_counter + 1}: "
                                  f"{follower.username}")
                media_to_like_url = self.get_media_url(media_id)
                if not self.persistence.check_already_liked(media_id=media_id):
                    if self.like(media_id, media_to_like_url):
                        self.like_followers_counter += 1
                        self.logger.info(
                            f"Liked media of your follower {follower.username} "
                            f"#{self.like_followers_counter}: id: {media_id}, "
                            f"url: {media_to_like_url}")
                        return True
                else:
                    self.logger.debug(
                        f"You already liked media: id: {media_id}, url: "
                        f"{media_to_like_url} of your follower "
                        f"{follower.username}")
            except Exception as exc:
                self.logger.exception(exc)

        return False

    def new_auto_mod_unlike(self):
        if self.iteration_ready('unlike'):
            self.init_next_iteration('unlike')
            media_id = self.persistence.get_medias_to_unlike()
            media_url = self.get_media_url(media_id)
            if media_id:
                self.logger.debug(
                    f"Trying to unlike media #{self.like_counter + 1}: id: "
                    f"{media_id}, url: {media_url}")
                if self.unlike(media_id, media_url):
                    self.like_counter += 1
                    self.logger.info(f"Unliked media #{self.like_counter}: "
                                     f"id: {media_id}, url: {media_url}")
                    return True
            else:
                self.logger.debug("Nothing to unlike right now")

    def get_followers_count(self, username):
        url_info = self.url_user_detail % username
        resp = self.s.get(url_info)
        if resp.status_code == 200:
            try:
                all_data = json.loads(
                    re.search("window._sharedData = (.*?);</script>", resp.text, re.DOTALL).group(1)
                )
            except AttributeError as e:
                self.logger.critical(repr(e))
            followers_count = all_data['entry_data']['ProfilePage'][0][
                'graphql']['user']['edge_followed_by']['count']
        elif resp.status_code == 429:
            self.logger.critical(
                f"It seems like Instagram detected and blocked bot's actions. "
                f"Maybe big numbers are set to actions like 'followers_per_run'"
                f"or 'follow_attempts' setting in a configuration. Please "
                f"decrease them and wait for some time before start the bot "
                f"again. Also it is a good idea to delete your "
                f"'{self.session_file}.session' file before that")
            exit(1)
        else:
            self.logger.warning(
                f"Could not retrieve number of followers of user {username}, "
                f"url: {url_info}. Status code: {resp.status_code}")
            followers_count = 0

        return followers_count

    def verify_account_name(self, username):
        if not self.keywords:
            return True

        for keyword in self.keywords:
            if username.find(keyword) >= 0:
                return True

        try:
            url = self.url_user_detail % username
            r = self.s.get(url)
            all_data = json.loads(
                re.search(
                    "window._sharedData = (.*?);</script>",
                    r.text,
                    re.DOTALL,
                ).group(1)
            )
            biography = all_data['entry_data']['ProfilePage'][0][
                'graphql'
            ]['user']['biography']

            if biography:
                for keyword in self.keywords:
                    if biography.find(keyword) >= 0:
                        return True

        except Exception as exc:
            self.logger.debug(f"Cannot retrieve user {username}'s biography")
            self.logger.exception(exc)

        self.logger.debug(f"Will not follow user {username}: does not meet "
                          f"keywords requirement. Keywords are not found.")
        return False

    def verify_account_followers(self, username):
        if not self.user_min_follow and not self.user_max_follow:
            return True

        followers = self.get_followers_count(username)
        if followers:
            if followers < self.user_min_follow:
                self.logger.debug(f"Will not follow user {username}: does not "
                                  f"meet user_min_follow requirement")
                return False

            if self.user_max_follow and followers > self.user_max_follow:
                self.logger.debug(f"Will not follow user {username}: does not "
                                  f"meet user_max_follow requirement")
                return False
        else:
            return False
        return True

    def verify_account(self, username):
        return username != self.user_login \
               and self.verify_account_name(username) \
               and self.verify_account_followers(username)

    def new_auto_mod_follow(self, media):
        user_id = media['node']['owner']['id']
        username = self.get_username_by_user_id(user_id)

        self.logger.debug(f"Trying to follow user #{self.follow_counter + 1}: "
                          f"id: {user_id}, username: {username}")

        if self.persistence.check_already_followed(user_id=user_id):
            self.logger.debug(f"Will not follow {username}: user was already "
                              f"followed before")
            return False
        else:
            if not self.verify_account(username):
                return False

        if self.follow(user_id=user_id, username=username):
            return True

        return False

    def populate_from_feed(self):
        medias = self.get_medias_from_recent_feed()

        try:
            for mediafeed_user in medias:
                feed_username = mediafeed_user["node"]["owner"]["username"]
                feed_user_id = mediafeed_user["node"]["owner"]["id"]
                # print(self.persistence.check_if_userid_exists( userid=feed_user_id))
                if not self.persistence.check_if_userid_exists(userid=feed_user_id):
                    self.persistence.insert_username(
                        user_id=feed_user_id, username=feed_username
                    )
                    self.logger.debug(f"Inserted user {feed_username} from recent feed")
        except Exception as exc:
            self.logger.warning("Notice: could not populate from recent feed")
            self.logger.exception(exc)

    def new_auto_mod_unfollow(self):
        if self.iteration_ready('unfollow'):
            self.init_next_iteration('unfollow')
            user = self.persistence.get_username_to_unfollow_random()
            if user:
                self.logger.debug(f"Trying to unfollow user "
                                  f"#{self.unfollow_counter + 1}: "
                                  f"{user.username}")
                if self.auto_unfollow(user):
                    return True

    # new Method splitted from new_auto_mod_unfollow
    def new_auto_mod_unfollow_from_feed(self):
        if self.unfollow_from_feed:
            try:
                if (
                        time.time() > self.next_iteration["Populate"]
                        and self.unfollow_recent_feed is True
                ):
                    self.populate_from_feed()
                    self.next_iteration["Populate"] = time.time() + (
                        self.generate_time(360)
                    )
            except Exception as exc:
                self.logger.warning(
                    "Notice: Could not populate from recent feed right now"
                )
                self.logger.exception(exc)

            log_string = f"Trying to unfollow #{self.unfollow_counter + 1}:"
            self.logger.debug(log_string)
            self.auto_unfollow()
            self.next_iteration["Unfollow"] = time.time() + self.generate_time(
                self.unfollow_delay
            )

    def auto_unfollow(self, user):
        user_id = user.id
        user_name = user.username
        if not user_name:
            _username = self.get_username_by_user_id(user_id=user_id)
            if _username:
                user_name = _username
            else:
                self.logger.debug(f"Cannot resolve username from user id: "
                                  f"{user_id}")
                return False

        verify_unfollow_result = self.verify_unfollow(user_name)

        if verify_unfollow_result == 'unfollow':
            return self.unfollow(user_id, user_name)
        elif verify_unfollow_result == 'skip':
            self.persistence.update_follow_time(user_id=user_id)
            return True
        elif verify_unfollow_result == 'database':
            self.persistence.insert_unfollow_count(user_id=user_id)
            return True
        else:
            return False

    def verify_unfollow(self, user_name):
        user_info = self.get_user_info(user_name)
        if not user_info:
            self.logger.debug(f"User {user_name} was deleted: set an "
                              f"unfollow flag in database to this followed "
                              f"before user")
            return 'database'

        if self.unfollow_everyone:
            self.logger.debug("Ignore all verifications, unfollow_everyone flag"
                              " is set")
            return 'unfollow'

        self.logger.debug(f"User {user_name} has: {user_info.get('followers')} "
                          f"followers, {user_info.get('follows')} followings, "
                          f"{user_info.get('medias')} medias")

        if user_name in self.unfollow_whitelist:
            self.logger.debug(f"    > Will not unfollow {user_name}: the user "
                              f"is in the unfollow whitelist")
            return 'skip'

        if not self.account_is_followed_by_you(user_info):
            self.logger.debug("    > You are not following this account: set an"
                              " unfollow flag in database to this followed "
                              "before user")
            return 'database'

        if self.unfollow_selebgram and self.account_is_selebgram(user_info):
            self.logger.debug(f"    > Unfollowing {user_name}: the user is "
                              "probably a selebgram account")
            return 'unfollow'

        if self.unfollow_probably_fake and self.account_is_fake(user_info):
            self.logger.debug(f"    > Unfollowing {user_name}: the user is "
                              f"probably a fake account")
            return 'unfollow'

        if self.unfollow_inactive and not self.account_is_active(user_info):
            self.logger.debug(f"    > Unfollowing {user_name}: the user is "
                              f"not active")
            return 'unfollow'

        if self.unfollow_not_following and \
                not self.account_is_following_you(user_info):
            self.logger.debug(f"    > Unfollowing {user_name}: the user is "
                              f"not following you")
            return 'unfollow'
        elif self.unfollow_not_following and \
                self.account_is_following_you(user_info):
            self.logger.debug(f"    > Skipping {user_name}: the user is "
                              f"still following you")
            return 'skip'

        return

    def get_user_info(self, user_name):
        url_tag = self.url_user_detail % user_name
        try:
            r = self.s.get(url_tag)
            if r.status_code == 404:
                return False

            raw_data = re.search("window._sharedData = (.*?);</script>",
                                 r.text, re.DOTALL).group(1)
            user_data = json.loads(raw_data)['entry_data']['ProfilePage'][0][
                'graphql']['user']
            user_info = dict(follows=user_data['edge_follow']['count'],
                             followers=user_data['edge_followed_by']['count'],
                             medias=user_data[
                                 'edge_owner_to_timeline_media']['count'],
                             follows_viewer=user_data['follows_viewer'],
                             followed_by_viewer=user_data['followed_by_viewer'],
                             requested_by_viewer=user_data[
                                 'requested_by_viewer'],
                             has_requested_viewer=user_data[
                                 'has_requested_viewer'])
            return user_info

        except Exception as exc:
            self.logger.exception(exc)
            return None

    def account_is_selebgram(self, user_info):
        return user_info.get("follows") == 0 or (user_info.get("followers") / user_info.get("follows") > 2)

    def account_is_fake(self, user_info):
        return user_info.get("followers") == 0 or (user_info.get("follows") / user_info.get("followers") > 2)

    def account_is_active(self, user_info):
        return user_info.get("medias") > 0 \
               and (user_info.get("follows") / user_info.get("medias") < 25) \
               and (user_info.get("followers") / user_info.get("medias") < 25)

    def account_is_following_you(self, user_info):
        return user_info.get("follows_viewer") or user_info.get("has_requested_viewer")

    def account_is_followed_by_you(self, user_info):
        return user_info.get("followed_by_viewer") or user_info.get("requested_by_viewer")

    def new_auto_mod_comments(self, media):
        if self.iteration_ready('comments') and \
                self.verify_media_before_comment(media):
            self.init_next_iteration('comments')
            comment_text = self.generate_comment()
            if "@username@" in comment_text:
                comment_text = comment_text.replace('@username@', media[
                    'node']['owner']['username'])

            media_id = media['node']['id']
            if not self.comment(media_id, comment_text):
                self.persistence.insert_media(media['node']['id'], 'Error')

    def init_next_iteration(self, action):
        self.next_iteration[action] = self.generate_time(
            getattr(self, action + '_delay', -2 * time.time())) + time.time()

    def iteration_ready(self, action):
        action_counter = getattr(self, action + "_counter", 0)
        action_counter_per_run = getattr(self, action + "_per_run", 0)
        registered_time = self.next_iteration.get(action, 0)
        return action_counter < action_counter_per_run \
            and 0 <= registered_time < time.time()

    def generate_comment(self):
        c_list = list(itertools.product(*self.comment_list))

        repl = [('  ', ' '), (' .', '.'), (' !', '!')]
        res = ' '.join(random.choice(c_list))
        for s, r in repl:
            res = res.replace(s, r)
        return res.capitalize()

    def verify_media_before_comment(self, media):
        media_code = media['node']['shortcode']
        url_check = self.url_media % media_code
        try:
            resp = self.s.get(url_check)
            warn = f"Could not comment media {media_code}, url: {url_check}: " \
                   f"status code: {resp.status_code}. Reason: {resp.text}"
            if resp.status_code == 200:
                raw_data = re.search(
                    "window.__additionalDataLoaded\\('/p/[\\w-]+/',(.*?)\\);",
                    resp.text, re.DOTALL).group(1)
                all_data = json.loads(raw_data)['graphql']['shortcode_media']

                if all_data['owner']['id'] == self.user_id:
                    self.logger.debug(f"This media {media_code}, url: "
                                      f"{url_check} is yours. Skipping it")
                    return False

                if all_data['comments_disabled'] \
                        or all_data['commenting_disabled_for_viewer']:
                    self.logger.debug(
                        f"Comments are disabled on this media {media_code}, "
                        f"url: {url_check}. Skipping it")
                    return False

                edges = all_data.get('edge_media_to_comment', None)
                if not edges:
                    edges = all_data.get('edge_media_to_parent_comment', None)

                comments = list(edges['edges'])
                for comment in comments:
                    if comment['node']['owner']['id'] == self.user_id:
                        self.logger.debug(f"This media {media_code}, url: "
                                          f"{url_check} is already commented by"
                                          f" you")
                        return False
                return True

            elif resp.status_code == 404:
                self.logger.warning(f"This media {media_code}, url: {url_check}"
                                    f"does not exist anymore")
                return False

            else:
                self.logger.warning(warn)
                return False

        except Exception as exc:
            self.logger.warning(warn)
            return False

    def get_medias_from_recent_feed(self):
        self.logger.debug(f"{self.user_login} : Get media id on recent feed")
        url_tag = "https://www.instagram.com/"
        try:
            r = self.s.get(url_tag)
            jsondata = re.search("additionalDataLoaded\('feed',({.*})\);", r.text).group(1)
            all_data = json.loads(jsondata.strip())
            media_on_feed = list(all_data["user"]["edge_web_feed_timeline"]["edges"])
            self.logger.debug(f"Media in recent feed = {len(media_on_feed)}")

        except Exception as exc:
            logging.exception(exc)
            media_on_feed = []
        return media_on_feed

    @staticmethod
    def sec_to_time(t):
        t = int(t)
        h = t // 3600
        t %= 3600
        m = t // 60
        t %= 60
        s = t
        if h == 0:
            mg = str(m) + (" minute, " if m == 1 else " minutes, ") + str(s) + \
                (" second" if s == 1 else " seconds")
            if m == 0:
                mg = str(s) + (" second" if s == 1 else " seconds")
        elif m == 0:
            if m == 0:
                mg = str(h) + (" hour, " if h == 1 else " hours, ") + str(s) + \
                  (" second" if s == 1 else " seconds")
        else:
            mg = str(h) + (" hour, " if h == 1 else " hours, ") + str(m) + \
                  (" minute, " if m == 1 else " minutes, ") + str(s) + \
                  (" second" if s == 1 else " seconds")
        return mg

    @staticmethod
    def generate_time(t):
        """ Make some random for next iteration"""
        return random.gauss(t, t/10)

    @staticmethod
    def time_dist(to_time, from_time):
        """
        Method to compare time.
        In terms of minutes result is
        from_time + result == to_time
        Args:
            to_time: datetime.time() object.
            from_time: datetime.time() object.
        Returns: int
            how much minutes between from_time and to_time
            if to_time < from_time then it means that
                to_time is on the next day.
        """
        to_t = to_time.hour * 60 + to_time.minute
        from_t = from_time.hour * 60 + from_time.minute
        midnight_t = 24 * 60
        return (midnight_t - from_t) + to_t if to_t < from_t else to_t - from_t

    @staticmethod
    def str2bool(value):
        return str(value).lower() in ["yes", "true"]
