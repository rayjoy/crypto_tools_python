#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import xlrd
from datetime import date,datetime

def read_excel(infile, outfile, cmd):
    wb = xlrd.open_workbook(filename=infile) # open file
    #print(wb.sheet_names()) # get all sheet name

    sheet1 = wb.sheet_by_index(0) # get sheet by index
    #sheet1 = wb.sheet_by_name('testsheet') #get sheet by name

    #print(sheet1.name, sheet1.nrows, sheet1.ncols)

    #rows = sheet1.row_values(2)
    #cols = sheet1.col_values(3)
    #print(rows)
    #print(cols)
    #print(sheet1.cell(1,1).value)
    #print(sheet1.cell_value(1,0))
    #print(sheet1.row(1)[0].value)

    print("command: " + cmd)
    f = open(outfile, 'w')

    cmd_count = 0
    for row in range(0, sheet1.nrows):
        #if sheet1.cell(row, 4).value == cmd:
        if sheet1.cell(row, 6).value.find(cmd) == 0 :
            cmd_count += 1
            # print(sheet1.cell(row, 1).value)
            section_name = cmd + '_' + str(row + 1)
            # print(section_name)

            f.write('[' + section_name + ']' + '\n')
            f.write('in  = ' + sheet1.cell(row, 6).value + '\n')
            f.write('out = ' + sheet1.cell(row, 7).value + '\n')
    print("Process over, total command: " + str(cmd_count))
    f.close()

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("you need input like this: ")
        print(" getcmd_from_excel.py execl_file config_file command")
        print(" getcmd_from_excel.py demo.xls testFC.ini FC")
        exit()

    read_excel(sys.argv[1], sys.argv[2], sys.argv[3])
