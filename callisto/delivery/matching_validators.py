import logging
from collections import OrderedDict

from six.moves.urllib.parse import parse_qs, urlsplit
from django.core.exceptions import ValidationError
from django.forms import URLField

logger = logging.getLogger(__name__)


def clean_url(url):
    url_field = URLField()
    return url_field.clean(url.strip())


def twitter_validation_function(value):
        generic_twitter_urls = [
                'i',
                'following',
                'followers',
                'who_to_follow',
                'settings',
                'search',
                'tos',
                'privacy',
                'about',
            ]
        path = None
        try:
            url = clean_url(value)
            url_parts = urlsplit(url)
            # check if acceptable domain
            domain = url_parts[1]
            if not (domain == 'twitter.com' or domain == 'www.twitter.com' or domain == 'mobile.twitter.com'):
                return None
            path = url_parts[2].strip('/').split('/')[0].lower()
        except ValidationError:
            if value.startswith('@'):
                path = value[1:]
        # TODO: validate against allowed username characters
        # https://github.com/SexualHealthInnovations/callisto-core/issues/181
        if not path or path == "" or len(path) > 15 or path in generic_twitter_urls:
            return None
        else:
            return path


twitter_validation_info = {'validation': twitter_validation_function,
                           'example': 'https://twitter.com/twitter_handle or @twitter_handle',
                           'unique_prefix': 'twitter'}

'''
 NOTE: because identifiers are irreversibly encrypted and Facebook was the original matching identifier, Facebook
 identifiers are stored plain, with the prefix "www.facebook.com/" stripped. All other identifiers should be prefixed
 to allow for global uniqueness from Facebook profile identifiers.
'''

def facebook_validation_function(url):
        try:
            url = clean_url(url)
        except ValidationError:
            return None
        url_parts = urlsplit(url)
        # check if acceptable domain
        domain = url_parts[1]
        if not (domain == 'facebook.com' or domain.endswith('.facebook.com')):
            return None
        path = url_parts[2].strip('/').split('/')[0].lower()
        generic_fb_urls = [
            'messages',
            'hashtag',
            'events',
            'pages',
            'groups',
            'bookmarks',
            'lists',
            'developers',
            'topic',
            'help',
            'privacy',
            'campaign',
            'policies',
            'support',
            'settings',
            'games']
        if path == "profile.php":
            path = parse_qs(url_parts[3]).get('id')[0]
        # TODO: validate against allowed username characteristics
        # https://github.com/SexualHealthInnovations/callisto-core/issues/181
        if not path or path == "" or path.endswith('.php') or path in generic_fb_urls:
            return None
        else:
            return path

facebook_validation_info = {'validation': facebook_validation_function,
                            'example': 'http://www.facebook.com/johnsmithfakename',
                            'unique_prefix': ''}

'''
    potential options for identifier_domain_info, used in SubmitToMatchingForm
    identifier_domain_info is an ordered dictionary of matching identifiers
        key:
            the type of identifier requested
                example: 'Facebook profile URL' for Facebook
        value:
            a dictionary with
                a globally unique prefix (see note about Facebook's) to avoid cross-domain matches
                a validation function
                    should return None for invalid entries & return a minimal unique (within domain) path for valid
                an example input

    will return on first valid option tried
    see MatchingValidation.facebook_only (default)
'''

facebook_only = OrderedDict([('Facebook profile URL', facebook_validation_info)])
twitter_only = OrderedDict([('Twitter username/profile URL', twitter_validation_info)])
facebook_or_twitter = OrderedDict([('Facebook profile URL', facebook_validation_info),
                                   ('Twitter username/profile URL', twitter_validation_info)])
