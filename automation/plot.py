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


def get_plots(matcher, tdir, mrate):
    assert os.path.isdir(tdir)

    plots = []
    for x in os.listdir(tdir):
        d = os.path.join(tdir, x)
        if not os.path.isdir(d):
            continue
        m = re.match(r"(?:imix|pkt-(\d+))-(\d+)-(\d+)", x)
        if not m:
            continue
        if m.group(2) != mrate:
            continue
        if not matcher.match(x):
            continue
        pvals = [int(x) if x is not None else 0 for x in m.groups()]
        g = os.path.join(d, "*.pcap.gz")
        gm = glob.glob(g)
        if not gm:
            print(f"No PCAP in {g}")
            sys.exit(1)
        plots.append((pvals, gm[0]))

    splots = sorted(plots)
    plots = []
    for pval, ppath in splots:
        if not pval[2]:
            pname = f"no-traffic-{pval[1]}M"
        elif pval[0]:
            pname = f"{pval[0]}-{pval[2]}%"
        else:
            pname = f"imix-{pval[2]}%"
        plots.append(pname)
        plots.append(ppath)

    return plots


def do_run(rname, plotrow, ax, tableax):
    if len(plotrow) % 2:
        print("Incorrect name path pairs")
        sys.exit(1)

    dar = []
    seqno = []
    names = []
    mindatalen = 0
    for i in range(0, len(plotrow), 2):

        name, fpath = plotrow[i], plotrow[i + 1]
        if not os.path.exists(f"{fpath}.decode"):
            logging.info("%s", f"Processing Data for {name} from {fpath}")
            cmd = ("tshark -td -T fields -e frame.number -e frame.time_delta " +
                   f"-e ip.src -e ip.dst -e ip.proto -e esp.sequence -r {fpath} > {fpath}.decode")
            subprocess.run(cmd, shell=True, check=True)

        logging.info("%s", f"Processing Data for {name} from {fpath}.decode")
        filedata = open(f"{fpath}.decode").read().splitlines()

        # throw out the first and last couple entries
        filedata = [x.split("\t") for x in filedata[5:-5]]
        mindatalen = len(filedata) if not mindatalen else min(mindatalen, len(filedata))

        src = filedata[0][2]
        dst = filedata[0][3]
        proto = filedata[0][4]
        for pkt in filedata:
            if [src, dst, proto] != pkt[2:5]:
                logging.error("%s",
                              f"Unexpected packet in stream: {pkt[2:5]} != {src},{dst},{proto}")

        names.append(name)
        seqno.append([int(x[5]) for x in filedata])
        dar.append([float(x[1]) for x in filedata])

    # Get the histogram data.
    dar = [x[:mindatalen] for x in dar]
    seqno = [x[:mindatalen] for x in seqno]

    std = [np.std(x) for x in dar]
    mean = [np.mean(x) for x in dar]
    names = [f"{x} μ: {y:.2e} σ: {z:.2e}" for x, y, z in zip(names, mean, std)]

    # [ (hist, edges), ... ]
    bincount = 25

    # hgs = [np.histogram(x, bins=bincount) for x in dar]
    # # Collect some stats on each data type
    # for i, name in enumerate(names):
    #     coefvar = (std[i] / mean[i]) * 100
    #     sigpct = []
    #     # Find percentage of population falling withing n-sigma
    #     sigcnt = [0, 0, 0]
    #     sigpct = [0, 0, 0]
    #     popcnt = len(dar[i])
    #     last = dar[i]
    #     for j in range(len(sigpct), 0, -1):
    #         this = [x for x in last if abs(x - mean[i]) <= j * std[i]]
    #         last = this
    #         sigcnt[j - 1] = len(this)
    #         sigpct[j - 1] = (sigcnt[j - 1] / popcnt) * 100
    #     logging.info("%s", f"{name}: coefvar = {coefvar}, sigpct: {sigpct}")

    # Now find the x-min and x-max based on 3 std deviations from the mean
    xmin, xmax = None, None
    for i in range(0, len(dar)):
        _xmin = mean[i] - 6 * std[i]
        _xmax = mean[i] + 6 * std[i]
        if xmin is None:
            xmin, xmax = _xmin, _xmax
        else:
            xmin = min(_xmin, xmin)
            xmax = max(_xmax, xmax)

    ymax = None
    logr = False
    for x in ax[0:2]:
        #n, bins, patches = plt.hist(dar, log=False, rwidth=0.2, align='mid', bins=100)
        n, bins, _ = x.hist(dar, bins=bincount, log=logr, label=names)
        # logr = True
        x.set_title(f"Delta Arrival Times: {rname}")
        x.tick_params(labelrotation=45)
        x.grid(True)

        # Get maximum count for first graph
        if ymax is None:
            ymax = n.max()
        # x.legend(names)

    # For compariing we maybe dont want to limit to X*sigma range
    ax[0].set_xlim(left=xmin, right=xmax)
    ax[0].legend(names, loc="center")

    ax[1].set_ylim(top=int(ymax * .005))

    # Now let's plot a simple line chart
    for i, name in enumerate(names[:3]):
        ax[i + 2].plot(seqno[i], dar[i], label=name)
        ax[i + 2].set_title(name)

    # cnames = [f"# slots [10^{i-1}, 10^{i})" for i in range(1, 5)]
    # for r in range(len(names)):
    #     lower = 0
    #     for l in range(1, 5):
    #         lower = 10**(l-1)
    #         upper = 10**l

    # tbl = plt.table(cellText=cell_text
    #                 colLabels=cnames,
    #                 rowLabels=names,
    #                 loc='bottom')

    # # Textbox is 3rd column
    # x = ax[2]


def main(*margs):
    parser = argparse.ArgumentParser()
    parser.add_argument("plots", nargs="*", help="list of plotname,filename tuples")
    parser.add_argument("--mrate", help="rate to plot")
    parser.add_argument("--match", default=".*", help="regex for matching result dirs to plot")
    parser.add_argument("--verbose", action="store_true", help="rate to plot")
    args = parser.parse_args(*margs)

    autovpp.log.init_util(args)

    matcher = re.compile(args.match)

    plots = []
    rnames = []
    if not args.mrate:
        plots.append(args.plots)
        rnames.append("")
    for subdir in args.plots:
        if not os.path.isdir(subdir):
            continue
        plots.append(get_plots(matcher, subdir, args.mrate))
        rnames.append(subdir)

    # figsize is in inches.
    fig = plt.figure(figsize=(16, 9))
    cols = 3
    outer = gridspec.GridSpec(len(plots),
                              cols,
                              left=.05,
                              bottom=.10,
                              right=.95,
                              top=.95,
                              wspace=0.2,
                              hspace=0.3,
                              figure=fig)

    # fig, axs = plt.subplots(nrows=len(plots), ncols=2)
    for i in range(len(plots)):
        # middle = gridspec.GridSpecFromSubplotSpec(2,
        #                                           1,
        #                                           subplot_spec=outer[i],
        #                                           wspace=0.1,
        #                                           hspace=0.1)
        # inner = gridspec.GridSpecFromSubplotSpec(1,
        #                                          2,
        #                                          subplot_spec=middle[0],
        #                                          wspace=0.1,
        #                                          hspace=0.1)
        # tableax = plt.Subplot(fig, middle[1])
        tableax = None
        # inner = gridspec.GridSpecFromSubplotSpec(1,
        #                                          2,
        #                                          subplot_spec=outer[i],
        #                                          wspace=0.1,
        #                                          hspace=0.1)

        axs = [fig.add_subplot(outer[i, j]) for j in range(2)]
        gs2 = gridspec.GridSpecFromSubplotSpec(3, 1, hspace=0.6, subplot_spec=outer[i, 2])
        axs.extend([fig.add_subplot(gs2[j]) for j in range(3)])
        do_run(rnames[i], plots[i], axs, tableax)

    # fig.tight_layout()
    # plt.ylabel("Count")
    # plt.subplots_adjust(left=0, bottom=0, right=1, top=1, wspace=0, hspace=0)
    plt.show()


if __name__ == "__main__":
    try:
        main()
    except Exception as ex:
        from traceback import format_exc
        logging.error("Got Exception in main: %s\n%s", str(ex), format_exc())
        sys.exit(1)
