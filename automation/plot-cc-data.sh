D1=d1
D2=d2

tdir=/tmp/autovpp-chopps/latest
d1jf=$tdir/vpp-stats-$D1.json
d2jf=$tdir/vpp-stats-$D2.json
d1cf=$tdir/vpp-stats-$D1.csv
d2cf=$tdir/vpp-stats-$D2.csv

if false; then
    jq -r '.[]."1" | select(. == null | not) | (."/net/ipsec/sa/iptfs/tx-pps"|tostring) + " " + (."/net/ipsec/sa/iptfs/tx-rtt"|tostring) + " " + (."/net/ipsec/sa/iptfs/tx-lossrate"|tostring)' < $d1jf > $d1cf
    jq -r '.[]."1" | select(. == null | not) | (."/net/ipsec/sa/iptfs/tx-pps"|tostring) + " " + (."/net/ipsec/sa/iptfs/tx-rtt"|tostring) + " " + (."/net/ipsec/sa/iptfs/tx-lossrate"|tostring)' < $d2jf > $d2cf
fi

d1cf=$tdir/vpp-fast-stat-$D1.csv
d2cf=$tdir/vpp-fast-stat-$D2.csv

gnuplot-qt --persist <<- EOF
        set xlabel "Label"
        set ylabel "Label2"
        set title "Graph title"
        set term x11
        plot "${d1cf}" using 1:3 with lines, "${d2cf}" using 1:3 with lines
EOF

#../build-root/build-vpp_debug-native/vpp/bin/c2cpel --input /tmp/autovpp-chopps/latest/d1-events-0.clib --output-file d1-events-0.cpel
#/home/chopps/w-local/vpp/build-root/install-vpp_debug-native/vpp/bin/cpeldump --input d1-events-0.cpel  | grep pps|less
#
#000:00:02:450:990 workers 1 cc-update           RTT 201250 LR 0 X (pps) 32
