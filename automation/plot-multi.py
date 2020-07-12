#!/usr/bin/env python
# -*- coding: utf-8 eval: (yapf-mode 1) -*-
#
# June 16 2020, Christian Hopps  <chopps@labn.net>
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
import argparse
import logging
import os
import re
import subprocess
import sys

import matplotlib.pyplot as plt
import numpy as np

import autovpp.log
# from matplotlib import colors
# from matplotlib.tocker import PercentFormatter


def do_run(plots, ax, xmax_arg=None):
    if len(plots) % 2:
        print("Incorrect name path pairs")
        sys.exit(1)

    # keyed by spi
    esp_filedata = {}

    # keyed by src IP
    user_filedata = {}

    esp_name = ""
    user_name = ""

    count = 0
    for i in range(0, len(plots), 2):
        count += 1
        name, fpath = plots[i], plots[i + 1]

        F_TIME = 0
        F_IPSRC = 1
        F_IPDST = 2  # pylint: disable=W0612
        F_IPPROTO = 3
        F_ESPSPI = 4
        if not os.path.exists(f"{fpath}.decode2"):
            logging.info("%s", f"Processing Packets for {name} from {fpath}")
            cmd = ("tshark -T fields -e frame.time_relative -e ip.src " +
                   f"-e ip.dst -e ip.proto -e esp.spi -r {fpath} > {fpath}.decode2")
            subprocess.run(cmd, shell=True, check=True)

        logging.info("%s", f"Processing Data for {name} from {fpath}.decode2")
        filedata = open(f"{fpath}.decode2").read().splitlines()

        # throw out the first and last couple entries
        filedata = [re.sub(r",\d+$", "", x).split("\t") for x in filedata[5:-5]]

        # # Check that all the packets are the same
        # src = filedata[0][F_IPSRC]
        # dst = filedata[0][F_IPDST]
        # proto = filedata[0][F_IPPROTO]
        # for pkt in filedata:
        #     if [src, dst, proto] != pkt[F_IPSRC:F_IPPROTO + 1]:
        #         logging.error("%s",
        #                       f"Unexpected packet in stream: {pkt[1:4]} != {src},{dst},{proto}")

        # Sort file data into streams
        for x in filedata:
            if int(x[F_IPPROTO]) == 50:
                esp_name = name
                try:
                    spi = int(x[F_ESPSPI], 16)
                except:
                    import pdb
                    pdb.set_trace()
                if spi not in esp_filedata:
                    esp_filedata[spi] = [x]
                else:
                    esp_filedata[spi].append(x)
            else:
                user_name = name
                src = x[F_IPSRC]
                if src not in user_filedata:
                    user_filedata[src] = [x]
                else:
                    user_filedata[src].append(x)

    def get_deltas(type_filedata):
        type_arrivals = {}
        type_deltas = {}
        for k, data in type_filedata.items():
            _arrivals = [float(x[F_TIME]) for x in data]
            _deltas = [0.0]
            for i in range(1, len(data)):
                _deltas.append(_arrivals[i] - _arrivals[i - 1])

            type_arrivals[k] = _arrivals
            type_deltas[k] = _deltas
        return type_arrivals, type_deltas

    esp_arrivals, esp_deltas = get_deltas(esp_filedata)
    user_arrivals, user_deltas = get_deltas(user_filedata)
    all_arrivals = {**user_arrivals, **esp_arrivals}

    # Get the histogram data.
    def get_labels(name, deltas):
        assert deltas
        std = {k: np.std(deltas[k]) for k in deltas}
        mean = {k: np.mean(deltas[k]) for k in deltas}
        names = {k: f"{name} μ: {mean[k]:.2e} σ: {std[k]:.2e}" for k in deltas}

        # Now find the y-min and y-max based on 3 std deviations from the mean
        ymin = min([mean[k] - mean[k] * .5 for k in deltas])
        ymax = max([mean[k] + mean[k] * .5 for k in deltas])

        return names, ymin, ymax

    esp_names, esp_ymin, esp_ymax = get_labels(esp_name, esp_deltas)
    user_names, _, _ = get_labels(user_name, user_deltas)

    xmin, xmax = None, None
    for k in all_arrivals:
        _xmin = min(all_arrivals[k])
        _xmax = max(all_arrivals[k])
        if xmin is None:
            xmin = _xmin
            xmax = _xmax
        else:
            xmin = min(xmin, _xmin)
            xmax = max(xmax, _xmax)

    # # Reset xmin/xmax to 0 based
    # xmax = xmax - xmin
    # for i in range(count):
    #     arrivals[i] = [x - xmin for x in arrivals[i]]
    # xmin = 0

    if xmax_arg is not None:
        xmax = min(xmax_arg, xmax)

    # Now let's plot a simple line chart
    #
    # TFS plot
    #
    ax[0].set_xlim([xmin, xmax])
    ax[0].set_ylim(esp_ymin, esp_ymax)
    ax[0].set_title(esp_name)
    ax[0].ticklabel_format(useOffset=False)
    ax[0].tick_params(labelrotation=45)
    for k in esp_arrivals:
        ax[0].plot(esp_arrivals[k], esp_deltas[k], label=esp_names[k])

    # If we only have the TFS dataset we are done
    if not user_arrivals:
        return

    ax[1].set_title(user_name)
    ax[1].ticklabel_format(useOffset=False)
    ax[1].tick_params(labelrotation=45)
    if xmax <= 2:
        # If this is <= 2 second test, number of bins is number of packets
        for k in user_arrivals:
            ax[1].hist(user_arrivals[k],
                       bins=len(user_arrivals[k]),
                       range=[xmin, xmax],
                       label=user_names[k],
                       histtype="stepfilled")
    else:
        # If this is > 2 second test, number of bins is manageably fixed
        for k in user_arrivals:
            ax[1].hist(user_arrivals[k],
                       bins=1000,
                       range=[xmin, xmax],
                       label=user_names[k],
                       histtype="stepfilled")


def main(*margs):
    parser = argparse.ArgumentParser()
    parser.add_argument("plots", nargs="*", help="list of plotname,filename tuples")
    parser.add_argument("--output", help="save to a file")
    parser.add_argument("--xmax", type=float, help="max X value")
    parser.add_argument("--verbose", action="store_true", help="rate to plot")
    args = parser.parse_args(*margs)

    autovpp.log.init_util(args)

    # figsize is in inches.
    #fig, axs = plt.subplots(nrows=len(args.plots) // 2, ncols=1)
    _, axs = plt.subplots(figsize=(16 * 3 / 2, 9 * 3 / 2), nrows=2, ncols=1)
    # fig = plt.figure(figsize=(16, 9))
    do_run(args.plots, axs, args.xmax)

    # fig.tight_layout()
    # plt.ylabel("Count")
    # plt.subplots_adjust(left=0, bottom=0, right=1, top=1, wspace=0, hspace=0)
    if args.output:
        plt.savefig(args.output, dpi=300)
    else:
        plt.show()


if __name__ == "__main__":
    try:
        main()
    except Exception as ex:
        from traceback import format_exc
        logging.error("Got Exception in main: %s\n%s", str(ex), format_exc())
        sys.exit(1)
