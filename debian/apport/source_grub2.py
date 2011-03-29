'''apport package hook for grub2

Author: Jean-Baptiste Lallement <jeanbaptiste.lallement@gmail.com>

This program is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 3 of the License, or (at your
option) any later version.  See http://www.gnu.org/copyleft/gpl.html for
the full text of the license.
'''
from apport.hookutils import *
import os

def check_shell_syntax(path):
    ''' Check the syntax of a shell script '''
    try:
        subprocess.check_call(['/bin/sh','-n', path], stderr=open(os.devnull,'w'))
    except subprocess.CalledProcessError:
        return False
    return True

def _attach_file_filtered(report, path, key=None):
    '''filter out password from grub configuration'''
    if not key:
        key = path_to_key(path)

    if os.path.exists(path):
        with open(path,'r') as f:
            filtered = [l if not l.startswith('password')
                        else '### PASSWORD LINE REMOVED ###'
                        for l in f.readlines()]
            report[key] = ''.join(filtered)

def add_info(report):
    if report['ProblemType'] == 'Package':
        # To detect if root fs is a loop device
        attach_file(report, '/proc/cmdline','ProcCmdLine')
        _attach_file_filtered(report, '/etc/default/grub','EtcDefaultGrub')

        invalid_grub_script = []
        if not check_shell_syntax('/etc/default/grub'):
            invalid_grub_script.append('/etc/default/grub')

        # Check scripts in /etc/grub.d since some users directly change
        # configuration there
        grubdir='/etc/grub.d'
        for f in os.listdir(grubdir):
            fullpath=os.path.join(grubdir, f)
            if f != 'README' and os.access(fullpath, os.X_OK) \
               and not check_shell_syntax(fullpath):
                invalid_grub_script.append(fullpath)
                attach_file(report, fullpath)

        # TODO: Add some UI to ask if the user modified the invalid script
        # and if he still wants to report it
        if invalid_grub_script:
            report['InvalidGrubScript'] = ' '.join(invalid_grub_script)

if __name__ == '__main__':
    r = {}
    r['ProblemType'] = 'Package'
    add_info(r)
    for k, v in r.iteritems():
        print '%s: "%s"' % (k, v)
        print "========================================"
