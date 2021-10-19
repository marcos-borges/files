#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
**Module**: Duplicates.py
        :synopsis: Tool to find host duplicates.
        :platform: Tools
        :level: basic
.. moduleauthor:: Marcos Ferreira
.. versionadded:: 0.0.1
    Initial release
"""
import argparse
import base64
import json
import ntpath
import requests
import socket
import sys
import time
from collections import Counter

class Connection(Exception):
    pass

class Duplicates:
    version = '0.0.1'
    name = "Duplicates"
    description = "Find for duplicated hosts."

    def __init__(self, argv):
        """
            Initialize all stuff
        """
        self.baseCSUri = 'https://api.crowdstrike.com'
        self.csengine = [False, time.time(), 0, 0]
        self.headers = {'Content-Type': 'application/json',
                        'accept': 'application/json', }
        self.access_token = None
        self.argv = argv
        self.body = None
        self.code = None
        self.json = None
        self.parse_args()
        self.token = None
        self.toke_type = None
        self.verifySSL = None

    def is_json(self, data):
        try:
            json.loads(data)
            return True
        except ValueError as error:
            return False

    def parse_args(self):
        """Parse the arguments provided on the command line.

        Returns: a pair (continue, exit_code). If continue is False,
          the exit_code should be returned.
        """
        parser = argparse.ArgumentParser(
            usage='%(prog)s [options]', formatter_class=argparse.RawDescriptionHelpFormatter, add_help=True)
        options = parser.add_argument_group('Options')
        options.add_argument(
            '-c', '--cskey', help='CrowdStrike API authentication (clientID:secretID)', required=True)
        options.add_argument(
            '-bm', '--bios_manufacturer', help='DISABLE bios manufacturer comparison to find duplicates. (default: true)', default=True, action='store_false')
        options.add_argument(
            '-bv', '--bios_version', help='DISABLE bios version comparison to find duplicates. (default: true)', default=True, action='store_false')
        options.add_argument(
            '-m', '--mac_address', help='DISABLE mac address comparison to find duplicates. (default: true)', default=True, action='store_false')
        options.add_argument(
            '-sn', '--serial_number', help='DISABLE serial number comparison to find duplicates. (default: true)', default=True, action='store_false')
        options.add_argument(
            '-sm', '--system_manufacturer', help='DISABLE system manufacturer comparison to find duplicates. (default: true)', default=True, action='store_false')
        options.add_argument(
            '-sp', '--system_product_name', help='DISABLE system product name comparison to find duplicates. (default: true)', default=True, action='store_false')
        options.add_argument(
            '-V', '--verbose', help='verbose mode', action='store_true')
        options.add_argument(
            '-q', '--quiet', help='quiet mode', action='store_true')
        options.add_argument('-v', '--version', action='version',
                             version='%(prog)s {}'.format(self.version))
        parser.parse_args(self.argv, namespace=Duplicates)

        if self.verbose and not self.quiet:
            self.verboseMode = True
        else:
            self.verboseMode = False

    def printMsg(self, message='', width=60, divisor=False, end=False, center=False):
        result = ''

        messageList = message.split('\n')
        for current in range(len(messageList)):
            message = messageList[current]
            while len(message) > width:
                result = result + "# {} #\n".format(message[0:width])
                message = message[width:]
            if current == len(messageList)-1:
                if center:
                    if not len(message) % 2 == 0:
                        message = message + ' '
                    result = result + "#{0}{1}{0}#\n#{2}#".format(' ' * (((width + 2) - len(message))/2),
                                                                  message, ' ' * (width + 2))
                else:
                    result = result + "# {}{}#\n#{}#".format(
                        message, ' ' * ((width + 1) - len(message)), ' ' * (width + 2))
            else:
                if center:
                    if not len(message) % 2 == 0:
                        message = message + ' '
                    result = result + "#{0}{1}{0}#\n".format(' ' * (((width + 2) - len(message))/2),
                                                             message)
                else:
                    result = result + "# {}{}#\n".format(
                        message, ' ' * ((width + 1) - len(message)))

        if divisor:
            result = '{}\n#{}#'.format('#' * (width + 4), ' ' * (width + 2))

        if not self.quiet:
            print(result)

    def progressbar(self, current, total):
        # Progress bar
        current = int(current)
        total = int(total)

        progress = '[{:=5d}/{:=5d}]'.format(current, total)
        filled_len = int(round(30 * current / float(total)))
        percents = round(100.0 * current / float(total), 1)
        bar = '{}{}'.format('=' * filled_len, '-' * (30 - filled_len))

        sys.stdout.write('{}{}# {}[{}]  {}{} Done{}#\n'.format('\x1b[1A',
                                                               '\x1b[2K',
                                                               progress,
                                                               bar,
                                                               percents,
                                                               '%', ' ' *
                                                               (71 - len('{}{}# {}[{}]  {}{} Done'.format('\x1b[1A',
                                                                                                          '\x1b[2K',
                                                                                                          progress,
                                                                                                          bar,
                                                                                                          percents,
                                                                                                          '%')))))
        sys.stdout.flush()

    def _request(self, url, method, headers='', data='', params=''):
        """
        Establish HTTP connection using called method.

        Returns: HTTP response in dictionary format.
        """
        response = ''
        self.headers.update(headers)
        while True:
            try:
                prepared = requests.Request(
                    method.upper(), url, headers=headers, data=data, params=params).prepare()

                if self.verboseMode:
                    message = '{}\n{}\n{}\n\n{}'.format(
                        '-----------BEGIN REQUEST-----------',
                        prepared.method + ' ' + prepared.url,
                        '\n'.join('{}: {}'.format(k, v)
                                  for k, v in prepared.headers.items()),
                        prepared.body,
                    )
                    if self.verboseMode:
                        self.printMsg(message)

                self.session = requests.Session()
                response = self.session.send(prepared)

                if self.verboseMode:
                    message = '{}\n\nStatus-Code:{}\n{}\n\nContent: {}'.format(
                        '-----------BEGIN RESPONSE-----------',
                        response.status_code,
                        '\n'.join('{}: {}'.format(k, v)
                                  for k, v in response.headers.items()), response.content
                    )
                    if self.verboseMode:
                        self.printMsg(message)
            except KeyboardInterrupt:
                sys.exit()
            except Exception as e:
                self.printMsg(
                    "Unexpected error:\n{}\n\nWe will try to continue, let's see.".format(str(e)))

                def response(): return None
                setattr(response, 'status_code', False)
                break
            break

        return response

    def connectCS(self):
        self.headers = {"accept": "application/json",
                        "Content-Type": "application/x-www-form-urlencoded"}
        self.cskey = (self.cskey).split(':')
        request = self._request(
            self.baseCSUri + '/oauth2/token', 'POST', headers=self.headers, data={'client_id': self.cskey[0], 'client_secret': self.cskey[1]})
        if request.status_code in [200, 201]:
            content = json.loads(request.content.decode("utf-8"))
            self.access_token = content['access_token']
            self.headers = {"accept": "application/json",
                            "authorization": "bearer " + self.access_token}
            return True
        else:
            return False

    def disconnectCS(self):
        headers = {"accept": "application/json",
                   "Content-Type": "application/x-www-form-urlencoded",
                   "Authorization": "Basic " + base64.b64encode(('{}:{}'.format(self.cskey[0], self.cskey[1]).encode('ascii'))).decode('ascii')}

        request = self._request(
            self.baseCSUri + '/oauth2/revoke', 'POST', headers=headers, data={'token': self.access_token})
        if request.status_code in [200, 201]:
            content = json.loads(request.content.decode("utf-8"))
        return True

    def getHosts(self, offset=0):
        content = {}
        self.headers['Content-Type'] = 'application/json'

        request = self._request(
            self.baseCSUri + '/devices/queries/devices/v1?sort=hostname.desc&offset=' + str(offset), 'GET', headers=self.headers)

        if request.status_code in [200, 202]:
            content = json.loads(request.content.decode("utf-8"))
            content['status_code'] = request.status_code
        else:
            content = json.loads(request.content.decode("utf-8"))
            content['status_code'] = request.status_code
            content['resources'] = []

        return content

    def getDetails(self, ids):
        content = {}
        self.headers['Content-Type'] = 'application/json'
        request = self._request(
            self.baseCSUri + '/devices/entities/devices/v1?ids=' + ids, 'GET', headers=self.headers)
        if request.status_code in [200, 201]:
            content = json.loads(request.content.decode("utf-8"))
            content['status_code'] = request.status_code
        else:
            content = json.loads(request.content.decode("utf-8"))
            content['status_code'] = request.status_code
            content['resources'] = []

        return content

    def removeHost(self, ids):
        content = {}
        data = json.dumps({"ids": ids})
        self.headers['Content-Type'] = 'application/json'
        request = self._request(
            self.baseCSUri + '/devices/entities/devices-actions/v2?action_name=hide_host', 'POST', headers=self.headers, data=data)
        if request.status_code in [200, 201, 202]:
            content = json.loads(request.content.decode("utf-8"))
            content['status_code'] = request.status_code
        else:
            content = json.loads(request.content.decode("utf-8"))
            content['status_code'] = request.status_code
            content['resources'] = []

        return content

    ##################################################################################
    # Entry point for command-line execution
    ##################################################################################
    def main(self):
        try:
            self.printMsg(divisor=True)
            start = time.time()
            dfilter = ['hostname']
            dfilter.append(
                'bios_manufacturer') if self.bios_manufacturer else None
            dfilter.append('bios_version') if self.bios_version else None
            dfilter.append('mac_address') if self.mac_address else None
            dfilter.append('serial_number') if self.serial_number else None
            dfilter.append(
                'system_manufacturer') if self.system_manufacturer else None
            dfilter.append(
                'system_product_name') if self.system_product_name else None

            # Initialize connection
            if self.connectCS():
                ids = ''
                aids = []
                aidsDetails = []
                pduplicates = {}
                toDeleteAIDs = []
                noDeleteAIDs = []

                hosts = self.getHosts()
                aids = aids + hosts['resources']

                if len(hosts['resources']) > 0:
                    ids = hosts['resources'][0]
                    if len(hosts['resources']) > 1:
                        for aid in hosts['resources'][1:]:
                            ids += "&ids={}".format(aid)
                    aidsDetails = self.getDetails(ids)['resources']

                while hosts['meta']['pagination']['offset'] < hosts['meta']['pagination']['total']:
                    hosts = self.getHosts(
                        offset=hosts['meta']['pagination']['offset'])
                    aids = aids + hosts['resources']
                    if len(hosts['resources']) > 0:
                        ids = hosts['resources'][0]
                        if len(hosts['resources']) > 1:
                            for aid in hosts['resources'][1:]:
                                ids += "&ids={}".format(aid)
                        aidsDetails = aidsDetails + \
                            self.getDetails(ids)['resources']

                if len(aids) != hosts['meta']['pagination']['total']:
                    self.printMsg('Something went wrong! Was expected {} AIDs, but the list have {}. Quiting!'.format(
                        hosts['meta']['pagination']['total'], len(aids)))
                    sys.exit()

                hostCounter = Counter([k['hostname']
                                       for k in aidsDetails if k.get('hostname')])

                for k, v in hostCounter.items():
                    if v > 1:
                        tempList = []
                        for aid in aidsDetails:
                            if 'hostname' in aid:
                                if aid['hostname'] == k:
                                    aidN = {}
                                    for key in (dfilter + ['device_id', 'last_seen']):
                                        if key in aid:
                                            aidN[key] = aid[key]
                                    tempList.append(aidN)
                                pduplicates[k] = tempList
                        pduplicates[k] = sorted(
                            pduplicates[k], key=lambda x: x['last_seen'], reverse=True)
                    else:
                        for aid in aidsDetails:
                            if 'hostname' in aid:
                                if aid['hostname'] == k:
                                    noDeleteAIDs.append(aid['device_id'])

                for k, v in pduplicates.items():
                    vduplicate = {}
                    for i in v[:1]:
                        noDeleteAIDs.append(i['device_id'])
                        for key in dfilter:
                            if key in i:
                                vduplicate[key] = i[key]

                    for i in v[1:]:
                        cduplicate = {}
                        for key in dfilter:
                            if key in i:
                                cduplicate[key] = i[key]

                        if cduplicate == vduplicate:
                            toDeleteAIDs.append(i['device_id'])
                        else:
                            noDeleteAIDs.append(i['device_id'])

                confirmDeleteList = {}

                for aid in toDeleteAIDs:
                    for aidd in aidsDetails:
                        if aid == aidd['device_id']:
                            confirmDeleteList[aidd['device_id']] = {}
                            for key in (dfilter + ['device_id', 'last_seen']):
                                if key in aidd:
                                    confirmDeleteList[aidd['device_id']
                                                      ][key] = aidd[key]

                if len(toDeleteAIDs) > 0:
                    self.printMsg("{}".format(confirmDeleteList))
                    self.printMsg("A total of {} devices have been evaluated.\nYou are about to remove a total of {} devices.\n".format(
                        len(noDeleteAIDs) + len(toDeleteAIDs), len(toDeleteAIDs)))

                    answer = ""
                    while answer not in ["y", "n"]:
                        answer = input(
                            "{0}{1}{0}# Are you sure [Y/N]? ".format('\x1b[1A', '\x1b[2K')).lower()
                        self.printMsg('\x1b[1A')
                    # return answer == "n"

                    if answer != 'y':
                        sys.exit()
                    else:
                        for toDeleteAIDsChunk in (toDeleteAIDs[pos:pos + 100] for pos in range(0, len(toDeleteAIDs), 100)):
                            rmHosts = self.removeHost(toDeleteAIDsChunk)
                            if len(rmHosts['errors']) > 0:
                                self.printMsg(
                                    "The following error have occured:\n{}".format(rmHosts['errors']))
                            else:
                                self.printMsg("{} devices have been removed.\n".format(
                                    len(rmHosts['resources'])))

                else:
                    self.printMsg("A total of {} devices have been evaluated.\nNo duplicates found. Review your filter options\n".format(
                        len(noDeleteAIDs) + len(toDeleteAIDs)))

            else:
                self.printMsg("Failed to connect.")

            # END
        except KeyboardInterrupt:
            sys.exit()
        except Exception as e:
            exc = sys.exc_info()[2]
            self.printMsg(
                "Unexpected error:\n{}\n\nError executing instruction at line {} from file {}.".format(str(e), exc.tb_lineno, exc.tb_frame.f_code.co_filename))
        finally:
            try:
                self.disconnectCS()
            except Exception as e:
                exc = sys.exc_info()[2]
                self.printMsg(
                    "Unexpected error:\n{}\n\nError executing instruction at line {} from file {}.".format(str(e), exc.tb_lineno, exc.tb_frame.f_code.co_filename))
            duration = "Script duration: {}s".format(int(time.time() - start))

            if not self.quiet:
                sys.stdout.write('{}#{}{} #\n'.format(
                    '', ' ' * (61 - len(duration)), duration))
                sys.stdout.write('{}{}\n'.format('', '#' * 64))

def main(argv=None):
    if len(sys.argv[1:]) == 0:
        sys.argv[1:].append("--help")
        ma = Duplicates(argv if argv else sys.argv[1:])
    else:
        ma = Duplicates(argv if argv else sys.argv[1:])
    return ma.main()

if __name__ == "__main__":
    sys.exit(main())
