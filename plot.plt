set term png size 1366, 768
set output "graph.png"
set xlabel 'Time (seconds)'
set ylabel 'Share of Execution Time'
set logscale x
set multiplot layout 1,2
set grid mxtics, xtics, ytics, mytics
set key left

set title "VM-Exec vs. Reset"
plot 'stats.txt' using 1:2 with lines title 'reset', 'stats.txt' using 1:3 with lines title 'vm-exec'

set title 'Rate of Cases/Sec'
set ylabel 'Cases/Sec'
#unset logscale x
plot 'stats.txt' using 1:5 with lines title 'Cases/Sec'
