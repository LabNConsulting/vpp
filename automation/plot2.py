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
import glob
import os
import re
import subprocess
import sys

import matplotlib.pyplot as plt
import matplotlib.gridspec as gridspec
import numpy as np

import autovpp.log
# from matplotlib import colors
# from matplotlib.tocker import PercentFormatter


def do_run(plots, ax, xmax_arg=None):
    if len(plots) % 2:
        print("Incorrect name path pairs")
        sys.exit(1)

    deltas = []
    arrivals = []
    names = []
    count = 0
    for i in range(0, len(plots), 2):
        count += 1
        name, fpath = plots[i], plots[i + 1]

        if not os.path.exists(f"{fpath}.decode2"):
            logging.info("%s", f"Processing Packets for {name} from {fpath}")
            cmd = (
                #f"tshark -T fields -e esp.sequence -e frame.time_delta -e ip.src -e ip.dst -e ip.proto -r {fpath} > {fpath}.decode2"
                f"tshark -T fields -e frame.time_relative -e frame.time_delta -e ip.src -e ip.dst -e ip.proto -r {fpath} > {fpath}.decode2"
            )
            subprocess.run(cmd, shell=True, check=True)

        logging.info("%s", f"Processing Data for {name} from {fpath}.decode2")
        filedata = open(f"{fpath}.decode2").read().splitlines()

        # throw out the first and last couple entries
        filedata = [re.sub(",\d+$", "", x).split("\t") for x in filedata[5:-5]]

        # Check that all the packets are the same
        src = filedata[0][2]
        dst = filedata[0][3]
        proto = filedata[0][4]
        for pkt in filedata:
            if [src, dst, proto] != pkt[2:5]:
                logging.error("%s",
                              f"Unexpected packet in stream: {pkt[2:5]} != {src},{dst},{proto}")

        names.append(name)
        arrivals.append([float(x[0]) for x in filedata])
        deltas.append([float(x[1]) for x in filedata])

    # Get the histogram data.

    std = [np.std(deltas[i]) for i in range(count)]
    mean = [np.mean(deltas[i]) for i in range(count)]
    names = [f"{names[i]} μ: {mean[i]:.2e} σ: {std[i]:.2e}" for i in range(count)]

    # Now find the y-min and y-max based on 3 std deviations from the mean
    ymin = [mean[i] - mean[i] * .5 for i in range(count)]
    ymax = [mean[i] + mean[i] * .5 for i in range(count)]

    xmin, xmax = min(arrivals[0]), max(arrivals[0])
    for i in range(1, count):
        xmin = min(xmin, min(arrivals[i]))
        xmax = max(xmax, max(arrivals[i]))

    # # Reset xmin/xmax to 0 based
    # xmax = xmax - xmin
    # for i in range(count):
    #     arrivals[i] = [x - xmin for x in arrivals[i]]
    # xmin = 0

    if xmax_arg is not None:
        xmax = min(xmax_arg, xmax)

    # Now let's plot a simple line chart
    # for i in range(count-1):
    i = 0
    ax[i].plot(arrivals[i], deltas[i])
    if i == 0:
        ax[i].set_ylim([ymin[i], ymax[i]])
    ax[i].set_xlim([xmin, xmax])
    ax[i].set_title(names[i])
    ax[i].ticklabel_format(useOffset=False)
    ax[i].tick_params(labelrotation=45)

    # If we only have the TFS dataset we are done
    if count < 2:
        return

    if xmax <= 2:
        # If this is <= 2 second test, number of bins is number of packets
        ax[1].hist(arrivals[1], bins=len(arrivals[0]), range=[xmin, xmax], histtype="stepfilled")
    else:
        # If this is > 2 second test, number of bins is manageably fixed
        ax[1].hist(arrivals[1], bins=1000, range=[xmin, xmax], histtype="stepfilled")
    ax[1].set_title(names[1])
    ax[1].ticklabel_format(useOffset=False)
    ax[1].tick_params(labelrotation=45)


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
    fig, axs = plt.subplots(figsize=(16 * 3 / 2, 9 * 3 / 2), nrows=2, ncols=1)
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

# tshark -td -T fields -e frame.number -e frame.time_delta -e ip.src -e ip.dst -e ip.proto -e esp.sequence -r
