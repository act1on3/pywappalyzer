import json
import requests
import re
from sys import argv

wappalyzer_database_url = 'https://raw.githubusercontent.com/AliasIO/wappalyzer/master/src/apps.json'


# get wappalyzer apps.json by URL
def get_wappalyzer_database():

    try:
        req = requests.get(wappalyzer_database_url)

    except requests.exceptions.ConnectionError as err:
        return False, 'ERROR', err

    try:
        db = json.loads(req.text)

        apps = db['apps']
        categories = db['categories']

        return True, apps, categories

    except json.decoder.JSONDecodeError as err:
        return False, 'ERROR', err


# Class describes target
class Target:
    """Description of Target class

    """
    def __init__(self, target, allow_redirects=False):

        self.allow_redirects = allow_redirects

        # session is used for cookies hardening
        session = requests.Session()
        req = session.get(target, allow_redirects=self.allow_redirects)

        self.cookies = session.cookies.get_dict()

        # retrieve all needed info from request
        self.headers, self.html, self.code, self.isRedirect, self.url = self.request_dumper(req)

        # w/o allowing redirects we haven't history
        if self.allow_redirects:

            # history init
            self.history = []
            for r in req.history:
                headers, html, code, is_redirect, url = self.request_dumper(r)

                data = {
                    "headers": headers,
                    "html": html,
                    "code": code,
                    "isRedirect": is_redirect,
                    "url": url
                }

                self.history.append(data)

        # preparation to analyze
        self.meta_tags = self.get_meta_tags()

    def __str__(self):

        # receive info about requests with history
        if self.allow_redirects and len(self.history) > 0:
            arr_data = []

            for req in self.history:
                arr_data.append('[' + str(req['code']) + '] ' + req['url'])

            arr_data.append('[' + str(self.code) + '] ' + self.url)
            data = '\n'.join(arr_data)

        # receive info about requests w/o history
        else:
            data = '[' + str(self.code) + '] ' + self.url

        return data

    def request_dumper(self, req):

        headers = req.headers

        html = req.text
        code = req.status_code
        is_redirect = req.is_redirect
        url = req.url

        return headers, html, code, is_redirect, url

    # method for retrieving Meta tags from html
    def get_meta_tags(self):
        regexp = r'<meta[^>]+>'
        meta_tags = re.findall(regexp, self.html, re.I)

        return meta_tags


# class describes technologie (wappalyzer database entity)
class Technology:
    """Description on Technology class

    :parameter app - dictionary of apps from wappalyzer
    :parameter categories - dictionary of categories from wappalyzer

    """
    def __init__(self, name, app, categories):

        self.name = name
        # define categories
        cats = app['cats']
        self.categories = []

        # source of finding. It will be used while analyzing
        self.source = None

        # retrieve name for every category id
        for cat in cats:
            self.categories.append(categories[str(cat)])

        # define all app parameters
        # url - str
        if 'url' in app.keys():
            self.url = app['url']
            self.hasUrl = True
        else:
            self.hasUrl = False

        # website - str
        if 'website' in app.keys():
            self.website = app['website']
            self.hasWebsite = True
        else:
            self.hasWebsite = False

        # meta - dict
        if 'meta' in app.keys():
            self.meta = app['meta']
            self.hasMeta = True
        else:
            self.hasMeta = False

        # implies - str and list
        if 'implies' in app.keys():
            self.implies = app['implies']
            self.hasImplies = True
        else:
            self.hasImplies = False

        # html - str and list
        if 'html' in app.keys():
            self.html = app['html']
            self.hasHtml = True

        else:
            self.hasHtml = False

        # headers - dict only
        if 'headers' in app.keys():
            self.headers = app['headers']
            self.hasHeaders = True

        else:
            self.hasHeaders = False

        # cookies - dict only
        if 'cookies' in app.keys():
            self.cookies = app['cookies']
            self.hasCookies = True

        else:
            self.hasCookies = False

        # excludes - str and list
        if 'excludes' in app.keys():
            self.excludes = app['excludes']
            self.hasExcludes = True

        else:
            self.hasExcludes = False

    def __str__(self):
        data = 'Name:\t' + self.name

        # print categories
        data += '\nCategories:'

        for cat in self.categories:
            data += '\t' + cat['name'] + '\n'

        # print source
        if self.source is not None:
            data += 'Source:\t' + self.source + '\n'

        return data


# bunch of analyzing methods
def analyze_headers(app_headers, tech_headers):

    for tech_header_name in tech_headers.keys():
        # tech_header_name - name of Header (e.g. X-Forwarded-For).
        # tech_headers[tech_header_name] - value of the Header

        # regexp should be transformed to good value
        regexp_header_value = parse_pattern(tech_headers[tech_header_name])

        for app_header_name in app_headers.keys():
            # verify that headers name are equal. They can be in not the same registries
            if app_header_name.lower() == tech_header_name.lower():
                search = re.search(regexp_header_value, app_headers[app_header_name], re.I)
                if search is not None:
                    return True


def analyze_cookies(app_cookies, tech_cookies):

    for tech_cookie_name in tech_cookies.keys():
        # similar to analyze headers logic, but
        # cookie name is provided from database as regexp
        regexp_cookie_name = parse_pattern(tech_cookie_name)
        regexp_cookie_value = parse_pattern(tech_cookies[tech_cookie_name])

        for app_cookie_name in app_cookies.keys():
            # verify that cookie name are equal to regexp.
            search_name = re.search(regexp_cookie_name, app_cookie_name, re.I)

            if search_name is not None:
                search_value = re.search(regexp_cookie_value, app_cookies[app_cookie_name], re.I)

                if search_value is not None:
                    return True


def analyze_html(app_html, tech_pattern):

    def verification(regexp):

        # try/catch block fixes issue. It occurs with pattern
        #  (?:<div class="sf-toolbar[^>]+?>[^]+<span class="sf-toolbar-value">([\\d.])+|<div id="sfwdt[^"]+" class="[^"]*sf-toolbar)\\;version:\\1
        try:
            search_html = re.search(regexp, app_html, re.I)

        except re.error:
            search_html = re.search(re.escape(regexp), app_html, re.I)

        if search_html is not None:
            return True
        else:
            return False

    # if html is list from database
    if type(tech_pattern) is list:
        for pattern in tech_pattern:
            pattern_regexp = parse_pattern(pattern)

            if verification(pattern_regexp):
                return True

    # if html is string from database
    else:
        pattern_regexp = parse_pattern(tech_pattern)

        if verification(pattern_regexp):
            return True


# app_meta is list with strings
# tech_meta is dict: "meta_tag_name": "meta_tag_value_regexp"
def analyze_meta(app_meta, tech_meta):

    # enumeration by meta tag names of technology
    for meta_tag_name in tech_meta.keys():

        # we are looking for meta with needed name or property
        meta_names_regexp = "(?:name|property)=[\"']" + meta_tag_name + "[\"']"

        # let's enumerate all meta tags from application
        for app_meta_value in app_meta:
            found_meta_names = re.search(meta_names_regexp, app_meta_value, re.I)

            # we found meta tag with that name
            if found_meta_names is not None:

                # let's find content value
                found_meta_content_regexp = "content=(\"|')([^\"']+)(\"|')"
                content_search = re.search(found_meta_content_regexp, app_meta_value, re.I)

                if content_search is not None:
                    # content value is existed
                    content = content_search.group()

                    # from content="value" to value
                    content = ''.join(content.split('content=')[1:])[1:-1]

                    # let's compare content value with tech meta tag value
                    tech_meta_value_regexp = parse_pattern(tech_meta[meta_tag_name])

                    tech_value_search = re.search(tech_meta_value_regexp, content, re.I)

                    if tech_value_search is not None:
                        return True

                    else:
                        return False

                else:
                    return False


def analyze_url(app_url, tech_url):

    def verification(tech):
        tech_url_regexp = parse_pattern(tech)

        search_url = re.search(tech_url_regexp, app_url, re.I)

        if search_url is not None:
            return True

        else:
            return False

    # if type is str
    if type(tech_url) is not list:
        return verification(tech_url)

    # if type is list
    else:
        for tech in tech_url:
            if verification(tech):
                return True

        # if for cycle is ended, but nothing wasn't found
        return False


# regexp from database should be transformed to good value
def parse_pattern(pattern):
    # https://github.com/AliasIO/wappalyzer/blob/master/src/wappalyzer.js#L361
    regexp = pattern.split('\\;')[0]

    return regexp


# TODO: add checking request history step
# main method for analyzing technologies into application
def analyze(target, apps, categories):

    def check_tech(tech):
        # headers verification
        if len(target.headers) > 0 and tech.hasHeaders:
            source = 'headers'

            # Verify that it's used technology
            if analyze_headers(target.headers, tech.headers):
                tech.source = source

                # end the loop, because we already identified that the tech is used
                return tech

        # cookies verification
        if len(target.cookies) > 0 and tech.hasCookies:
            source = 'cookies'

            # Verify that it's used technology
            if analyze_cookies(target.cookies, tech.cookies):
                tech.source = source

                # end the loop, because we already identified that the tech is used
                return tech

        # html verification
        if len(target.html) > 0 and tech.hasHtml:
            source = 'html'
            # Verify that it's used technology
            if analyze_html(target.html, tech.html):
                tech.source = source

                # end the loop, because we already identified that the tech is used
                return tech

        # meta verification
        if len(target.meta_tags) > 0 and tech.hasMeta:
            source = 'meta'

            if analyze_meta(target.meta_tags, tech.meta):
                tech.source = source

                # end the loop, because we already identified that the tech is used
                return tech

        # url verification
        if tech.hasUrl:
            source = 'url'

            if analyze_url(target.url, tech.url):
                tech.source = source

                # end the loop, because we already identified that the tech is used
                return tech

        # if is not found
        return None

    techs = []
    used_techs = []

    # prepare app database
    for app in apps.keys():
        tech = Technology(app, apps[app], categories)
        techs.append(tech)

    for tech in techs:
        is_used = check_tech(tech)

        if is_used is not None:
            used_techs.append(tech)

    # proccess of including/excluding
    implied = []
    excluded = []

    # create list of excluded
    for tech in used_techs:
        if tech.hasExcludes:
            # list or not
            if type(tech.excludes) is list:
                excluded += tech.excludes
            else:
                excluded.append(tech.excludes)

    # exclude
    # only unique
    excluded = list(set(excluded))

    if len(excluded) > 0:
        used_techs_filtered = []

        for tech in used_techs:
            if tech.name not in excluded:
                used_techs_filtered.append(tech)

    else:
        used_techs_filtered = used_techs

    # create list of included
    for tech in used_techs_filtered:
        if tech.hasImplies:
            # list or not
            if type(tech.implies) is list:
                implied += tech.implies
            else:
                implied.append(tech.implies)

    # implie
    # only unique
    implied = list(set(implied))

    if len(implied) > 0:
        for tech in techs:
            # check that technology is in implied list AND is not contained into used now
            if tech.name in implied and tech not in used_techs_filtered:
                tech.source = 'implied'
                used_techs_filtered.append(tech)

    # result
    return used_techs_filtered


# example of usage
if __name__ == '__main__':

    url = argv[1]

    # create Target class by URL
    t = Target(url, allow_redirects=True)

    # print target
    print(t)

    # define wappalyzer database
    status, apps, categories = get_wappalyzer_database()

    if status:
        # analyze it
        used_techs = analyze(t, apps, categories)

        for tech in used_techs:
            print(tech)

    else:
        print('ERROR')
