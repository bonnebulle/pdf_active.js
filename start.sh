#!/bin/bash
echo "PWD :"
echo  /var/www/@Dockers/@PDF_js_mozilla/moz/
echo "LOG :"
echo tail -f /var/www/@Dockers/@PDF_js_mozilla/moz/nohup.out
cd /var/www/@Dockers/@PDF_js_mozilla/moz/
nohup npx gulp server &
