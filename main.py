import requests
import json
import sys
import argparse
import time
import yaml

parser = argparse.ArgumentParser(description='Secure Email Content Filter Tool', prog='Email Sender Block')
parser.add_argument('--config_file', help='Configuration yaml file path, defaults to config.yaml in current directory',
                    required=False)
parser.add_argument('--filter-name', help='Name of the content filter to be modified',
                    required=False)
parser.add_argument('--sender', help='Email address to be added or removed',
                    required=False)
parser.add_argument('--action', help='ADD or Delete from content filter',
                    required=False)
parser.add_argument('--secure-email-url', help='IP address or hostname of Secure Email',
                    required=False)
parser.add_argument('--admin-user', help='Username for user with permissions in Secure Email to modify content filters',
                    required=False)
parser.add_argument('--admin-password',
                    help='Password for user with permissions in Secure Email to modify content filters',
                    required=False)


class SecureEmail:
    session = requests.Session()
    csrf = ''
    refer = ''
    cookie = ''

    def disable_verify(self):
        self.session.verify = False
        requests.packages.urllib3.disable_warnings()

    def get_csrf(self):
        response = self.session.get(self.secure_email_url, verify=False)
        self.refer = response.url
        self.cookie = 'sid=' + response.cookies.get('sid') + ';'
        page = response.text
        # page = requests.get(self.secure_email_url, verify=False).text
        for p in page.split('\n'):
            if 'CSRFKey' in p:
                hidden = p.split('input type="hidden"')
                for h in hidden:
                    if 'CSRFKey' in h:
                        try:
                            self.csrf = h.split('value="')[1].split('"')[0]
                        except:
                            continue

    def login(self):
        body = 'action=Login&referrer=""&screen=login&CSRFKey={0}&username={1}&password={2}'.format(
            self.csrf, self.usr, self.pwd
        )
        url = self.secure_email_url + '/login'
        response = self.session.post(url, data=body)
        if response.status_code != 200:
            raise Exception('Authentication failed, exiting')
        self.cookie = self.cookie + ' authenticated=' + self.session.cookies.get('authenticated') + ';'
        self.session.headers.update({'Cookie': self.cookie})

    def get_content_filters(self):
        url = self.secure_email_url + '/mail_policies/email_security_manager/incoming_content_filters'
        response = self.session.get(url)
        if response.status_code != 200:
            return ''
        content_filters = {}
        table_split = response.text.split('<tr')
        for t in table_split:
            if '<a href="' + self.secure_email_url in t and 'incoming_content_filters?' in t:
                hit_url = False
                filter_name = ''
                filter_url = ''
                table_data_split = t.split('\n')
                for td in table_data_split:
                    if '<a href="' + self.secure_email_url in td and not hit_url:
                        filter_url = td.split('"')[1]
                        hit_url = True
                    if hit_url and '<div id="' in td and '_rules_cf_pag' in td:
                        filter_name = td.split('"')[1].split('_rules_cf_pag')[0]
                    if filter_name != '' and filter_url != '':
                        content_filters.update({filter_name: filter_url})
                        break
        return content_filters

    def get_content_filter(self, url):
        self.session.headers.update({
            'Referer': self.refer + '/mail_policies/email_security_manager/incoming_content_filters'
        })
        self.session.get(url)

    def add_sender_email_block(self, sender, content_filter):
        filters = self.get_content_filters()
        if content_filter not in filters:
            return ''
        else:
            self.get_content_filter(filters[content_filter])
            order = str(int(filters[content_filter].split('filterIdx=')[1]) + 1)
        self.session.headers.update({
            'Referer': self.secure_email_url + '/mail_policies/email_security_manager/incoming_content_filter_edit'
        })
        data = 'addedit=add&description=&' \
               'screen=mail_policies.email_security_manager.content_filters.incoming_content_filters&' \
               'ruleidx=undefined&' \
               'ruletype=condition&' \
               'roles=&conditionLogicAnyOrAll=any' \
               '&ruleid=EnvelopeSender&' \
               'fname={0}&' \
               'rule_field_count=3&' \
               'action=AddEditRule&' \
               'order={1}&' \
               'radio=match_text&' \
               'operator=equals&' \
               'match_text={2}&' \
               'ldap_group=&' \
               'content_dict=Test&' \
               'CSRFKey={3}'.format(
            content_filter, order, sender, self.csrf
        )
        url = self.secure_email_url + '/mail_policies/email_security_manager/incoming_content_filter_edit'
        response = self.session.post(url, data=data)
        if response.status_code == 200:
            self.save_content_filter(content_filter, order)

    def delete_sender_email_block(self, sender, content_filter):
        filters = self.get_content_filters()
        if content_filter not in filters:
            return ''
        else:
            self.get_content_filter(filters[content_filter])
            order = str(int(filters[content_filter].split('filterIdx=')[1]) + 1)
        self.session.headers.update({
            'Referer': self.secure_email_url + '/mail_policies/email_security_manager/incoming_content_filter_edit'
        })
        data = 'action=DeleteRule&' \
               'description=&' \
               'screen=mail_policies.email_security_manager.content_filters.incoming_content_filters&' \
               'ruleidx=3&' \
               'ruletype=condition&' \
               'fname={0}&' \
               'order={1}&' \
               'conditionLogicAnyOrAll=any&' \
               'CSRFKey={3}'.format(content_filter, order, sender, self.csrf)
        url = self.secure_email_url + '/mail_policies/email_security_manager/incoming_content_filter_edit'
        response = self.session.post(url, data=data)
        if response.status_code == 200:
            self.save_content_filter(content_filter, order)

    def save_content_filter(self, filter_name, order):
        data = 'action=Save&' \
               'ruletype=&' \
               'ruleidx=0&' \
               'screen=mail_policies.email_security_manager.content_filters.incoming_content_filters&' \
               'fname={0}&' \
               'description=&' \
               'order={1}&' \
               'conditionLogicAnyOrAll=any&' \
               'CSRFKey={2}'.format(
            filter_name, order, self.csrf
        )
        self.session.headers.update({
            'Referer': self.secure_email_url + '/mail_policies/email_security_manager/incoming_content_filter_edit'
        })
        url = self.secure_email_url + '/mail_policies/email_security_manager/incoming_content_filter_edit'
        response = self.session.post(url, data=data)
        if response.status_code == 200:
            self.create_commit()

    def create_commit(self):
        referrer = self.secure_email_url + '/mail_policies/email_security_manager/incoming_content_filters'
        self.session.headers.update({
            'Referer': self.secure_email_url + '/mail_policies/email_security_manager/content_filters//incoming_content_filters'
        })
        url = self.secure_email_url + '/commit?referrer=' + referrer
        response = self.session.post(url)
        if response.status_code == 200:
            self.commit(referrer)

    def commit(self, referrer):
        data = 'action=Commit&' \
               'screen=commit&' \
               'logout=&' \
               'comment=&' \
               'CSRFKey={0}'.format(self.csrf)
        self.session.headers.update({'Referer': self.secure_email_url + '/commit?referrer=' + referrer})
        url = self.secure_email_url + '/commit'
        response = self.session.post(url, data=data)
        if response.status_code == 200:
            return True

    def __init__(self, url, username, password, secure=True):
        if secure:
            http_prefix = 'https://'
        else:
            http_prefix = 'http://'
        self.secure_email = url
        if not self.secure_email.startswith(http_prefix):
            self.secure_email_url = http_prefix + self.secure_email
        else:
            self.secure_email_url = url
        self.usr = username
        self.pwd = password
        self.get_csrf()
        self.session.headers = {
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
            'Accept-Encoding': 'gzip, deflate',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive',
            'Content-Type': 'application/x-www-form-urlencoded',
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:107.0) Gecko/20100101 Firefox/107.0',
            'Cookie': self.cookie,
            'Host': self.secure_email,
            'Origin': self.secure_email_url,
            'Referer': self.refer
        }
        self.login()


if __name__ == '__main__':
    args = parser.parse_args()
    if args.config_file:
        with open(args.config_file, 'r') as stream:
            try:
                cfg = yaml.safe_load(stream)
            except yaml.YAMLError as exc:
                print(exc)
    elif not args.config_file and not args.secure_email_url:
        with open('config.yaml', 'r') as stream:
            try:
                cfg = yaml.safe_load(stream)
            except yaml.YAMLError as exc:
                print(exc)
    else:
        cfg = {
            'content_filter': args.filter_name,
            'secure_email_url': args.secure_email_url,
            'action': args.action,
            'sender': args.sender,
            'admin_user': args.admin_user,
            'admin_password': args.admin_password
        }
    ces = SecureEmail(url=cfg['secure_email_url'], username=cfg['admin_user'], password=cfg['admin_password'])
    if cfg['action'].lower() != 'add' and cfg['action'].lower() != 'delete':
        sys.exit()
    if cfg['action'].lower() == 'add':
        ces.add_sender_email_block(cfg['sender'], cfg['content_filter'])
    if cfg['action'].lower() == 'delete':
        ces.delete_sender_email_block(cfg['sender'], cfg['content_filter'])
    #
