# -*- coding: utf-8 eval: (yapf-mode 1) -*-
# January 14 2020, Christian E. Hopps <chopps@labn.net>
#
# Copyright (c) 2020, LabN Consulting, L.L.C
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import logging
import logging.config
import logging.handlers
import os
import yaml

__dir_path__ = os.path.dirname(os.path.realpath(__file__))
g_logdir = None


def _init(args, deflogconf):
    global g_logdir  # pylint: disable=W0603

    logconf = args.logconf if hasattr(args, "logconf") else deflogconf
    verbose = args.verbose if hasattr(args, "verbose") else False
    savedir = os.getcwd()
    logdir = args.logdir if hasattr(args, "logdir") else savedir
    try:
        os.chdir(logdir)
        g_logdir = logdir
        if (logdir != savedir):
            print(f"Logs in: {logdir}")
        config = yaml.safe_load(open(logconf).read())
        if verbose:
            config['handlers']['console']['level'] = "DEBUG"
        logging.config.dictConfig(config)
    finally:
        os.chdir(savedir)


def init(args):
    _init(args, os.path.join(__dir_path__, "log.conf.yml"))


def init_util(args):
    _init(args, os.path.join(__dir_path__, "log-util.conf.yml"))
