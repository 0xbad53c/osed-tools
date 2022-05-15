#!/usr/bin/python3
import sys
import os
import subprocess
import re
import argparse

def read_gadgets_from_rp_file(file):
    gadgets = []
    # discard first few lines, as they do not matter
    with open(file, "r") as f:
        lines = f.readlines()
        instructionstart = 0

        # Determine start of the instructions
        for line in lines:
            instructionstart += 1
            if "A total of " in line:
                break

        for line in lines[instructionstart:]:
            gadgets.append(line)

    return gadgets

def filter_bad_char_gadgets(gadget_list, badchars, aslr):
    badchar_filtered_gadgets = []
    start = 0

    # in case of aslr, we want to start checking the address for badchars starting from the specified position
    if aslr != None:
        start = aslr

    for gadget in gadget_list:
        hex_address = gadget.split(":")[0].split("0x")[1]

        # generate badchar list
        split_badchars = []
        n  = 2
        for index in range(0, len(badchars), n):
            split_badchars.append(badchars[index : index + n])

        # convert hex address into list of pairs
        contains_bad_char = False
        for index in range(start, len(hex_address), n):
            if hex_address[index : index + n] in split_badchars:
                contains_bad_char = True
                break

        if contains_bad_char == False:
            badchar_filtered_gadgets.append(gadget)

    return badchar_filtered_gadgets

def filter_large_return_gadgets(gadget_list):
    # filter gadgets further: avoid large returns > 256 as these require too much junk
    r = re.compile(r'^0x[0-9a-fA-F]{8}:.* retn 0x[0-9a-fA-F]{4}')
    for gadget in list(filter(r.match, gadget_list)):
        offset = gadget.split("retn ")[1].split(" ;")[0]
        if int(offset, 0) > 255:
            gadget_list.remove(gadget)
    
    return gadget_list

# create empty file
def create_result_file(filename):
    with open(filename, "w") as f:
        pass
    
    return True

def append_result_file(filename, gadget_list, header, aslr, dll_name, image_base):
    start = 0
    dllname = "dllbase"

    if aslr != None:
        start = aslr

    if dll_name != None:
        dllname = dll_name

    with open(filename, "a") as f:
        f.write("===================" + header + "===================\n")
        for gadget in gadget_list:
            if start > 0:
                address = gadget.split(":")[0] # take the address part, parse it as int
                offset = int(address, 16) - int(image_base, 16) # parse image_base as hex and subtract
                "0x{:08x}".format(offset) # convert back to hex string
                gadget = gadget[start+2:] # also keep in mind 0x
                gadget = dllname + "+0x" + gadget

            f.write(gadget)
        f.write("\n")
    return True

def remove_gadgets_from_gadget_list(gadget_list, gadgets_to_be_removed):
    for gadget in gadgets_to_be_removed:
        if gadget in gadget_list:
            gadget_list.remove(gadget)

    return gadget_list

def remove_gadgets_from_gadget_list2(gadget_list, gadgets_to_be_removed):
    create_result_file("debug.txt")
    append_result_file("debug.txt", gadget_list, "debug", image_base)
    create_result_file("debug2.txt")
    append_result_file("debug2.txt", gadgets_to_be_removed, "debug", image_base)
    for gadget in gadgets_to_be_removed:
        if gadget in gadget_list:
            gadget_list.remove(gadget)

    return gadget_list

# Hunt for gadgets to nullify registers
# fetches max 5 instructions per register
def q1_null(gadget_list, register):
    gadgets = []
    r = re.compile(r'^0x[0-9a-fA-F]{8}: (xor|sub|sbb) ' + register + r', ' + register + ' ; ret') # xor|sub|sbb self, self = 0x00
    gadgets += list(filter(r.match, gadget_list))

    r = re.compile(r'^0x[0-9a-fA-F]{8}: (and|mov|mul) ' + register + r', 0x00000000 ; ret') # = 0x00000000
    gadgets += list(filter(r.match, gadget_list))

    return gadgets

# pop r32 instructions
# fetches max 5
def q1_pop(gadget_list, register):
    gadgets = []
    r = re.compile(r'^0x[0-9a-fA-F]{8}: pop ' + register + r' ; ret')
    gadgets += list(filter(r.match, gadget_list))

    return gadgets

# swap from current register into another
def q1_mov_to(gadget_list, register):
    gadgets = []
    r = re.compile(r'^0x[0-9a-fA-F]{8}: mov ' + register + r', [a-zA-Z]{3} ; ret')
    gadgets += list(filter(r.match, gadget_list))

    r = re.compile(r'^0x[0-9a-fA-F]{8}: push [a-zA-Z]{3} ; pop ' + register + r' ; ret')
    gadgets += list(filter(r.match, gadget_list))

    return gadgets

def q1_mov_from(gadget_list, register):
    gadgets = []
    r = re.compile(r'^0x[0-9a-fA-F]{8}: mov [a-zA-Z]{3}, ' + register + r' ; ret')
    gadgets += list(filter(r.match, gadget_list))

    r = re.compile(r'^0x[0-9a-fA-F]{8}: push ' + register + r' ; pop [a-zA-Z]{3} ; ret')
    gadgets += list(filter(r.match, gadget_list))

    return gadgets

def q1_xchg(gadget_list, register1, register2):
    gadgets = []
    r = re.compile(r'^0x[0-9a-fA-F]{8}: xchg ' + register1 + r', ' + register2 + r' ; ret')
    gadgets += list(filter(r.match, gadget_list))

    r = re.compile(r'^0x[0-9a-fA-F]{8}: xchg ' + register2 + r', ' + register1 + r' ; ret')
    gadgets += list(filter(r.match, gadget_list))

    return gadgets

# Hunt for additions of register values to register
def q1_add_reg(gadget_list, register):
    gadgets = []
    r = re.compile(r'^0x[0-9a-fA-F]{8}: (add|adc) ' + register + r', [a-zA-Z]{3} ; ret')
    gadgets += list(filter(r.match, gadget_list))

    return gadgets

# Hunt for additions of static values to register
def q1_add_val(gadget_list, register):
    gadgets = []
    r = re.compile(r'^0x[0-9a-fA-F]{8}: (add|adc) ' + register + r', 0xFFFFFF[0-9A-F]{2} ; ret') # can extend this to find more if needed, but better to do manually
    gadgets += list(filter(r.match, gadget_list))

    return gadgets

# Hunt for subtractions of register values to register
def q1_sub_reg(gadget_list, register):
    gadgets = []
    r = re.compile(r'^0x[0-9a-fA-F]{8}: (sub|sbc) ' + register + r', [a-zA-Z]{3} ; ret')
    gadgets += list(filter(r.match, gadget_list))

    return gadgets

# Hunt for subtractions of static values to register
def q1_sub_val(gadget_list, register):
    gadgets = []
    r = re.compile(r'^0x[0-9a-fA-F]{8}: (sub|sbc) ' + register + r', 0xFFFFFF[0-9A-F]{2} ; ret') # can extend this to find more if needed, but better to do manually
    gadgets += list(filter(r.match, gadget_list))

    return gadgets

# Hunt for or
def q1_or_to(gadget_list, register):
    gadgets = []
    r = re.compile(r'^0x[0-9a-fA-F]{8}: or ' + register + r', [a-zA-Z]{3} ; ret')
    gadgets += list(filter(r.match, gadget_list))

    return gadgets

def q1_or_from(gadget_list, register):
    gadgets = []
    r = re.compile(r'^0x[0-9a-fA-F]{8}: or [a-zA-Z]{3}, ' + register + r' ; ret')
    gadgets += list(filter(r.match, gadget_list))

    return gadgets

# Hunt for and
def q1_and_to(gadget_list, register):
    gadgets = []
    r = re.compile(r'^0x[0-9a-fA-F]{8}: and ' + register + r', [a-zA-Z]{3} ; ret')
    gadgets += list(filter(r.match, gadget_list))

    return gadgets

def q1_and_from(gadget_list, register):
    gadgets = []
    r = re.compile(r'^0x[0-9a-fA-F]{8}: and [a-zA-Z]{3}, ' + register + r' ; ret')
    gadgets += list(filter(r.match, gadget_list))

    return gadgets

def q1_mem_write(gadget_list, register):
    gadgets = []
    r = re.compile(r'^0x[0-9a-fA-F]{8}: mov dword \['+ register + r'\], [a-zA-Z]{3} ; ret')
    gadgets += list(filter(r.match, gadget_list))

    r = re.compile(r'^0x[0-9a-fA-F]{8}: mov dword \['+ register + r'\+0x0(4|8|C)\], [a-zA-Z]{3} ; ret')
    gadgets += list(filter(r.match, gadget_list))

    r = re.compile(r'^0x[0-9a-fA-F]{8}: mov word \['+ register + r'\], [a-zA-Z]{3} ; ret')
    gadgets += list(filter(r.match, gadget_list))

    r = re.compile(r'^0x[0-9a-fA-F]{8}: mov word \['+ register + r'\+0x0(4|8|C)\], [a-zA-Z]{3} ; ret')
    gadgets += list(filter(r.match, gadget_list))

    r = re.compile(r'^0x[0-9a-fA-F]{8}: mov byte \['+ register + r'\], [a-zA-Z]{3} ; ret')
    gadgets += list(filter(r.match, gadget_list))

    r = re.compile(r'^0x[0-9a-fA-F]{8}: mov byte \['+ register + r'\+0x0(4|8|C)\], [a-zA-Z]{3} ; ret')
    gadgets += list(filter(r.match, gadget_list))

    return gadgets

def q1_mem_read(gadget_list, register):
    gadgets = []
    r = re.compile(r'^0x[0-9a-fA-F]{8}: mov [a-zA-Z]{3}, dword \['+ register + r'\] ; ret')
    gadgets += list(filter(r.match, gadget_list))

    gadgets = []
    r = re.compile(r'^0x[0-9a-fA-F]{8}: mov [a-zA-Z]{3}, dword \['+ register + r'\+0x0(4|8|C)\] ; ret')
    gadgets += list(filter(r.match, gadget_list))

    # Can also implement or for this

    return gadgets

def q1_mov_from_esp(gadget_list, register):
    gadgets = []
    r = re.compile(r'^0x[0-9a-fA-F]{8}: mov '+ register + r', esp ; ret')
    gadgets += list(filter(r.match, gadget_list))

    r = re.compile(r'^0x[0-9a-fA-F]{8}: push esp ; pop '+ register + r' ; ret')
    gadgets += list(filter(r.match, gadget_list))

    r = re.compile(r'^0x[0-9a-fA-F]{8}:.*mov '+ register + r', esp.*; ret')
    long_gadgets = list(filter(r.match, gadget_list))
    gadgets += sorted(long_gadgets, key=len)

    return gadgets

def q1_inc(gadget_list, register):
    gadgets = []
    r = re.compile(r'^0x[0-9a-fA-F]{8}: inc '+ register + r' ; ret')
    gadgets += list(filter(r.match, gadget_list))

    return gadgets

def q1_dec(gadget_list, register):
    gadgets = []
    r = re.compile(r'^0x[0-9a-fA-F]{8}: dec '+ register + r' ; ret')
    gadgets += list(filter(r.match, gadget_list))

    return gadgets

# negate
def q1_neg(gadget_list, register):
    gadgets = []
    r = re.compile(r'^0x[0-9a-fA-F]{8}: neg '+ register + r'.*; ret')
    long_gadgets = list(filter(r.match, gadget_list))
    gadgets += sorted(long_gadgets, key=len)

    return gadgets

# shift right (can be improved by checking value later but usually not too many gadgets exist)
def q1_shr(gadget_list, register):
    gadgets = []
    r = re.compile(r'^0x[0-9a-fA-F]{8}: (shr|sar) '+ register + r', .*; ret')
    long_gadgets = list(filter(r.match, gadget_list))
    gadgets += sorted(long_gadgets, key=len)

    return gadgets

# ropnops
def q1_ropnops(gadget_list):
    # ropnops
    r = re.compile(r'^0x[0-9a-fA-F]{8}: ret')
    filtered_gadgets = list(filter(r.match, gadget_list))

    gadgets = sorted(filtered_gadgets, key=len)

    return gadgets

# breakpoints
def q1_bp(gadget_list):
    r = re.compile(r'^0x[0-9a-fA-F]{8}: int3')
    filtered_gadgets = list(filter(r.match, gadget_list))

    gadgets = sorted(filtered_gadgets, key=len)

    return gadgets

# check if register to pop into matches register param to avoid wrong categorization
# e.g. push esp ; pop esi; pop ebi; would be categorized as move to ebi while it should be pop esi
# also cover cases with multiple push instructions: push r32 ; push esp ; pop esi; pop ebi;
def pushpop_filter_gadgets(gadget_list, register, source_register):
    filtered_long_gadgets = []
    for gadget in gadget_list:
        instructions = gadget.split(":")[1].split(";")
        pushpop_list = [] # make list of only push pops in order of appearance
        push_esp_hit = False
        push_esp_index = 0
        target_register = ""

        for instruction in instructions:
            if " push " in instruction:
                pushpop_list.append(instruction)
            if " pop " in instruction:
                pushpop_list.append(instruction)

        for i in range(len(pushpop_list)):
            if push_esp_hit == True:
                if " pop " in pushpop_list[i]:
                    target_register = pushpop_list[i].split(" pop ")[1][0:3]
                    break
            if ("push " + source_register) in pushpop_list[i]:
                push_esp_hit = True
                push_esp_index = i

        if target_register == register:
            filtered_long_gadgets.append(gadget)

    return filtered_long_gadgets



def q2_pushpop_from_esp(gadget_list, register):
    gadgets = []

    r = re.compile(r'^0x[0-9a-fA-F]{8}:.*push esp.*pop '+ register + r'.*; ret')
    long_gadgets = list(filter(r.match, gadget_list))
    filtered_long_gadgets = pushpop_filter_gadgets(long_gadgets, register, "esp")

    gadgets += sorted(filtered_long_gadgets, key=len)

    return gadgets

# There is still some issue in this type of function, causing duplicates in long_gadgets
# could be related to q1 filter as well (future work)
def q2_mov_mov_from(gadget_list, register):
    gadgets = []
    r = re.compile(r'^0x[0-9a-fA-F]{8}:.*mov [a-zA-Z]{3}, ' + register + r'.*; ret')
    long_gadgets = list(filter(r.match, gadget_list))
    gadgets += sorted(long_gadgets, key=len)

    return gadgets

def q2_mov_mov_to(gadget_list, register):
    gadgets = []
    r = re.compile(r'^0x[0-9a-fA-F]{8}:.*mov ' + register + r', [a-zA-Z]{3} ;.*; ret')
    long_gadgets = list(filter(r.match, gadget_list))
    gadgets += sorted(long_gadgets, key=len)

    return gadgets

def q2_mov_pushpop(gadget_list, register):
    gadgets = []
    r = re.compile(r'^0x[0-9a-fA-F]{8}:.*push ' + register + r'.*pop [a-zA-Z]{3} ;.*; ret')
    long_gadgets = list(filter(r.match, gadget_list))
    gadgets += sorted(long_gadgets, key=len)

    return gadgets

def q2_mov_xchg(gadget_list, register):
    gadgets = []
    r = re.compile(r'^0x[0-9a-fA-F]{8}:.*xchg [a-zA-Z]{3}, ' + register + r' ;.*; ret')
    long_gadgets = list(filter(r.match, gadget_list))
    gadgets += sorted(long_gadgets, key=len)

    return gadgets


def q2_mem_write(gadget_list, register):
    gadgets = []
    r = re.compile(r'^0x[0-9a-fA-F]{8}:.*mov dword \['+ register + r'\], [a-zA-Z]{3}.*; ret')
    long_gadgets = list(filter(r.match, gadget_list))
    gadgets += sorted(long_gadgets, key=len)

    r = re.compile(r'^0x[0-9a-fA-F]{8}:.*mov dword \['+ register + r'\+0x0(4|8|C)\], [a-zA-Z]{3}.*; ret')
    long_gadgets = list(filter(r.match, gadget_list))
    gadgets += sorted(long_gadgets, key=len)

    r = re.compile(r'^0x[0-9a-fA-F]{8}:.*mov word \['+ register + r'\], [a-zA-Z]{3}.*; ret')
    long_gadgets = list(filter(r.match, gadget_list))
    gadgets += sorted(long_gadgets, key=len)

    r = re.compile(r'^0x[0-9a-fA-F]{8}:.*mov word \['+ register + r'\+0x0(4|8|C)\], [a-zA-Z]{3}.*; ret')
    long_gadgets = list(filter(r.match, gadget_list))
    gadgets += sorted(long_gadgets, key=len)

    r = re.compile(r'^0x[0-9a-fA-F]{8}:.*mov byte \['+ register + r'\], [a-zA-Z]{3}.*; ret')
    long_gadgets = list(filter(r.match, gadget_list))
    gadgets += sorted(long_gadgets, key=len)

    r = re.compile(r'^0x[0-9a-fA-F]{8}:.*mov byte \['+ register + r'\+0x0(4|8|C)\], [a-zA-Z]{3}.*; ret')
    long_gadgets = list(filter(r.match, gadget_list))
    gadgets += sorted(long_gadgets, key=len)

    return gadgets

def q2_mem_read(gadget_list, register):
    gadgets = []
    r = re.compile(r'^0x[0-9a-fA-F]{8}:.*mov [a-zA-Z]{3}, dword \['+ register + r'\].*; ret')
    long_gadgets = list(filter(r.match, gadget_list))
    gadgets += sorted(long_gadgets, key=len)

    gadgets = []
    r = re.compile(r'^0x[0-9a-fA-F]{8}:.*mov [a-zA-Z]{3}, dword \['+ register + r'\+0x0(4|8|C)\].*; ret')
    long_gadgets = list(filter(r.match, gadget_list))
    gadgets += sorted(long_gadgets, key=len)

    # Can also implement or for this

    return gadgets

# todo
# fix some instructions that do self manipulations and are mentioned in multiple categories
# find shortest mov r32, esp or push esp pop r32 instructions (10 candidates should be enough)
# enhance q2 quality further for mov alternatives to double-check if something performs and undo. E.g. mov ebx, eax ; pop ebx

# Filter gadgets of highest quality
def q1(filename, gadget_list, aslr, dll_name, image_base):
    r32 = ["eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"]

    # Hunt for gadgets to nullify registers
    q1_null_gadgets = []
    for r in r32:
        q1_null_gadgets_reg = q1_null(gadget_list, r)
        append_result_file(filename, q1_null_gadgets_reg[0:5], "null " + r, aslr, dll_name, image_base)
        q1_null_gadgets += q1_null_gadgets_reg
    gadget_list = remove_gadgets_from_gadget_list(gadget_list, q1_null_gadgets)

    # Hunt for pop gadgets
    q1_pop_gadgets = []
    for r in r32:
        q1_pop_gadgets_reg = q1_pop(gadget_list, r)
        append_result_file(filename, q1_pop_gadgets_reg[0:5], "pop " + r, aslr, dll_name, image_base)
        q1_pop_gadgets += q1_pop_gadgets_reg
    gadget_list = remove_gadgets_from_gadget_list(gadget_list, q1_pop_gadgets)

    # Hunt for xchg gadgets
    q1_xchg_gadgets = []
    r32_copy = r32.copy()
    for r1 in r32:
        if r1 in r32_copy:
            r32_copy.remove(r1)
        for r2 in r32_copy:
            q1_xchg_gadgets_reg = q1_xchg(gadget_list, r1, r2)
            append_result_file(filename, q1_xchg_gadgets_reg[0:5], "xchg " + r1 + " and " + r2, aslr, dll_name, image_base)
            q1_xchg_gadgets += q1_xchg_gadgets_reg
    gadget_list = remove_gadgets_from_gadget_list(gadget_list, q1_pop_gadgets)

    # Hunt for move to registry gadgets
    q1_mov_to_other_gadgets = []
    for r in r32:
        q1_mov_to_other_gadgets_reg = q1_mov_to(gadget_list, r)
        append_result_file(filename, q1_mov_to_other_gadgets_reg[0:5], "move to " + r, aslr, dll_name, image_base)
        q1_mov_to_other_gadgets += q1_mov_to_other_gadgets_reg
    
    # Hunt for move from registry gadgets
    q1_mov_from_other_gadgets = []
    for r in r32:
        q1_mov_from_other_gadgets_reg = q1_mov_from(gadget_list, r)
        append_result_file(filename, q1_mov_from_other_gadgets_reg[0:5], "move from " + r, aslr, dll_name, image_base)
        q1_mov_from_other_gadgets += q1_mov_from_other_gadgets_reg

    # remove together after functions to allow duplicates
    gadget_list = remove_gadgets_from_gadget_list(gadget_list, q1_mov_to_other_gadgets)
    gadget_list = remove_gadgets_from_gadget_list(gadget_list, q1_mov_from_other_gadgets)


    # Hunt for register additions
    q1_add_reg_gadgets = []
    for r in r32:
        q1_add_reg_gadgets_reg = q1_add_reg(gadget_list, r)
        append_result_file(filename, q1_add_reg_gadgets_reg, "add register value to " + r, aslr, dll_name, image_base)
        q1_add_reg_gadgets += q1_add_reg_gadgets_reg
    gadget_list = remove_gadgets_from_gadget_list(gadget_list, q1_add_reg_gadgets)

    # Hunt for value additions
    q1_add_val_gadgets = []
    for r in r32:
        q1_add_val_gadgets_reg = q1_add_val(gadget_list, r)
        append_result_file(filename, q1_add_val_gadgets_reg[0:5], "add static value to " + r, aslr, dll_name, image_base)
        q1_add_val_gadgets += q1_add_val_gadgets_reg
    gadget_list = remove_gadgets_from_gadget_list(gadget_list, q1_add_val_gadgets)

    # Hunt for register subtractions
    q1_sub_reg_gadgets = []
    for r in r32:
        q1_sub_reg_gadgets_reg = q1_sub_reg(gadget_list, r)
        append_result_file(filename, q1_sub_reg_gadgets_reg, "sub register value from " + r, aslr, dll_name, image_base)
        q1_sub_reg_gadgets += q1_sub_reg_gadgets_reg
    gadget_list = remove_gadgets_from_gadget_list(gadget_list, q1_sub_reg_gadgets)
    
    # Hunt for value subtractions
    q1_sub_val_gadgets = []
    for r in r32:
        q1_sub_val_gadgets_reg = q1_sub_val(gadget_list, r)
        append_result_file(filename, q1_sub_val_gadgets_reg[0:5], "sub static value from " + r, aslr, dll_name, image_base)
        q1_sub_val_gadgets += q1_sub_val_gadgets_reg
    gadget_list = remove_gadgets_from_gadget_list(gadget_list, q1_sub_val_gadgets)

    # Hunt for inc
    q1_inc_gadgets = []
    for r in r32:
        q1_inc_gadgets_reg = q1_inc(gadget_list, r)
        append_result_file(filename, q1_inc_gadgets_reg, "increment " + r, aslr, dll_name, image_base)
        q1_inc_gadgets += q1_inc_gadgets_reg
    gadget_list = remove_gadgets_from_gadget_list(gadget_list, q1_inc_gadgets)

    # Hunt for dec
    q1_dec_gadgets = []
    for r in r32:
        q1_dec_gadgets_reg = q1_dec(gadget_list, r)
        append_result_file(filename, q1_dec_gadgets_reg, "decrement " + r, aslr, dll_name, image_base)
        q1_dec_gadgets += q1_dec_gadgets_reg
    gadget_list = remove_gadgets_from_gadget_list(gadget_list, q1_dec_gadgets)

    # Hunt for or
    q1_or_to_gadgets = []
    for r in r32:
        q1_or_to_gadgets_reg = q1_or_to(gadget_list, r)
        append_result_file(filename, q1_or_to_gadgets_reg[0:5], "or gadgets to " + r + " (combine with 0x00000000 to get mv)", aslr, dll_name, image_base)
        q1_or_to_gadgets += q1_or_to_gadgets_reg
    
    q1_or_from_gadgets = []
    for r in r32:
        q1_or_from_gadgets_reg = q1_or_from(gadget_list, r)
        append_result_file(filename, q1_or_from_gadgets_reg[0:5], "or gadgets from " + r + " (combine with 0x00000000 to get mv)", aslr, dll_name, image_base)
        q1_or_from_gadgets += q1_or_from_gadgets_reg

    # remove together after functions to allow duplicates
    gadget_list = remove_gadgets_from_gadget_list(gadget_list, q1_or_to_gadgets)
    gadget_list = remove_gadgets_from_gadget_list(gadget_list, q1_or_from_gadgets)

    # Hunt for and
    q1_and_to_gadgets = []
    for r in r32:
        q1_and_to_gadgets_reg = q1_and_to(gadget_list, r)
        append_result_file(filename, q1_and_to_gadgets_reg[0:5], "and gadgets to " + r + " (combine with 0xffffffff to get mv)", aslr, dll_name, image_base)
        q1_and_to_gadgets += q1_and_to_gadgets_reg
    
    q1_and_from_gadgets = []
    for r in r32:
        q1_and_from_gadgets_reg = q1_and_from(gadget_list, r)
        append_result_file(filename, q1_and_from_gadgets_reg[0:5], "and gadgets from " + r + " (combine with 0xffffffff to get mv)", aslr, dll_name, image_base)
        q1_and_from_gadgets += q1_and_from_gadgets_reg

    # remove together after functions to allow duplicates
    gadget_list = remove_gadgets_from_gadget_list(gadget_list, q1_and_to_gadgets)
    gadget_list = remove_gadgets_from_gadget_list(gadget_list, q1_and_from_gadgets)

    # Hunt for memory writes
    q1_mem_write_gadgets = []
    for r in r32:
        q1_mem_write_gadgets_reg = q1_mem_write(gadget_list, r)
        append_result_file(filename, q1_mem_write_gadgets_reg[0:5], "memory write to " + r + " pointer", aslr, dll_name, image_base)
        q1_mem_write_gadgets += q1_mem_write_gadgets_reg
    gadget_list = remove_gadgets_from_gadget_list(gadget_list, q1_mem_write_gadgets)

    # Hunt for memory reads
    q1_mem_read_gadgets = []
    for r in r32:
        q1_mem_read_gadgets_reg = q1_mem_read(gadget_list, r)
        append_result_file(filename, q1_mem_read_gadgets_reg, "memory read from " + r + " pointer", aslr, dll_name, image_base)
        q1_mem_read_gadgets += q1_mem_read_gadgets_reg
    gadget_list = remove_gadgets_from_gadget_list(gadget_list, q1_mem_read_gadgets)

    # Hunt for shift right instructions (useful to prepend null bytes on mem addresses)
    q1_shr_gadgets = []
    for r in r32:
        q1_shr_gadgets_reg = q1_shr(gadget_list, r)
        append_result_file(filename, q1_shr_gadgets_reg[0:5], "shortest shift right " + r + " (useful to prepend null bytes on mem addresses)", aslr, dll_name, image_base)
        q1_shr_gadgets += q1_shr_gadgets_reg
    gadget_list = remove_gadgets_from_gadget_list(gadget_list, q1_shr_gadgets)

    # Hunt for shift right instructions (useful to prepend null bytes on mem addresses)
    q1_neg_gadgets = []
    for r in r32:
        q1_neg_gadgets_reg = q1_neg(gadget_list, r)
        append_result_file(filename, q1_neg_gadgets_reg[0:5], "negate " + r, aslr, dll_name, image_base)
        q1_neg_gadgets += q1_neg_gadgets_reg
    gadget_list = remove_gadgets_from_gadget_list(gadget_list, q1_neg_gadgets)

    # Hunt for ropnops
    q1_ropnop_gadgets = q1_ropnops(gadget_list)
    append_result_file(filename, q1_ropnop_gadgets[0:5], "ropnops", aslr, dll_name, image_base)
    gadget_list = remove_gadgets_from_gadget_list(gadget_list, q1_ropnop_gadgets)

    # Hunt for breakpoints
    q1_bp_gadgets = q1_bp(gadget_list)
    append_result_file(filename, q1_bp_gadgets[0:5], "breakpoints", aslr, dll_name, image_base)
    gadget_list = remove_gadgets_from_gadget_list(gadget_list, q1_bp_gadgets)

    # Find 5 shortest mov r32, esp (or push pop equivalent) per register
    q1_mov_from_esp_gadgets = []
    for r in r32:
        # no need to mov esp, esp
        if r != "esp":
            q1_mov_from_esp_reg = q1_mov_from_esp(gadget_list, r)
            append_result_file(filename, q1_mov_from_esp_reg[0:5], "5 shortest mov " + r + ", esp", aslr, dll_name, image_base)
            q1_mov_from_esp_gadgets += q1_mov_from_esp_reg
    gadget_list = remove_gadgets_from_gadget_list(gadget_list, q1_mov_from_esp_gadgets)

    # q1_filtered_gadgets = # sum of all lists
    # print("Number of Q1 gadgets: " + str(len(q1_gadgets)))


    return gadget_list

def q2(filename, gadget_list, aslr, dll_name, image_base):
    r32 = ["eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"]

    # Find 15 shortest push pop per register
    q2_pushpop_from_esp_gadgets = []
    for r in r32:
        # no need to mov esp, esp or ebp, esp
        if r != "esp" and r != "ebp":
            q2_pushpop_from_esp_reg = q2_pushpop_from_esp(gadget_list, r)
            append_result_file(filename, q2_pushpop_from_esp_reg[0:25], "25 shortest push esp ; pop " + r + " ; ", aslr, dll_name, image_base)
            q2_pushpop_from_esp_gadgets += q2_pushpop_from_esp_reg
    gadget_list = remove_gadgets_from_gadget_list(gadget_list, q2_pushpop_from_esp_gadgets)


    # Find 15 shortest mov from register
    q2_mov_mov_gadgets = []
    for r in r32:
        q2_mov_mov_gadgets_reg = q2_mov_mov_from(gadget_list, r)
        append_result_file(filename, q2_mov_mov_gadgets_reg[0:15], "15 shortest mov from " + r + " ; ", aslr, dll_name, image_base)
        q2_mov_mov_gadgets += q2_mov_mov_gadgets_reg[0:15]
    gadget_list = remove_gadgets_from_gadget_list(gadget_list, q2_mov_mov_gadgets)

    # Find 15 shortest mov to register
    q2_mov_mov_gadgets = []
    for r in r32:
        q2_mov_mov_gadgets_reg = q2_mov_mov_to(gadget_list, r)
        append_result_file(filename, q2_mov_mov_gadgets_reg[0:15], "15 shortest mov to " + r + " ; ", aslr, dll_name, image_base)
        q2_mov_mov_gadgets += q2_mov_mov_gadgets_reg[0:15]
    gadget_list = remove_gadgets_from_gadget_list(gadget_list, q2_mov_mov_gadgets)


    # Find 15 shortest push pop register
    q2_mov_pushpop_gadgets = []
    for r in r32:
        q2_mov_pushpop_gadgets_reg = q2_mov_pushpop(gadget_list, r)
        append_result_file(filename, q2_mov_pushpop_gadgets_reg[0:15], "15 shortest push pop from " + r + " ; ", aslr, dll_name, image_base)
        q2_mov_pushpop_gadgets += q2_mov_pushpop_gadgets_reg
    gadget_list = remove_gadgets_from_gadget_list(gadget_list, q2_mov_pushpop_gadgets)


    # Find 15 shortest xchg register
    q2_mov_xchg_gadgets = []
    for r in r32:
        q2_mov_xchg_gadgets_reg = q2_mov_xchg(gadget_list, r)
        append_result_file(filename, q2_mov_xchg_gadgets_reg[0:15], "15 shortest xchg from " + r + " ; ", aslr, dll_name, image_base)
        q2_mov_xchg_gadgets += q2_mov_xchg_gadgets_reg
    gadget_list = remove_gadgets_from_gadget_list(gadget_list, q2_mov_xchg_gadgets)

    # Find 15 shortest mem write register
    q2_mem_write_gadgets = []
    for r in r32:
        q2_mem_write_gadgets_reg = q2_mem_write(gadget_list, r)
        append_result_file(filename, q2_mem_write_gadgets_reg[0:15], "15 shortest mem write for " + r + " ; ", aslr, dll_name, image_base)
        q2_mem_write_gadgets += q2_mem_write_gadgets_reg
    gadget_list = remove_gadgets_from_gadget_list(gadget_list, q2_mem_write_gadgets)

    # Find 15 shortest mem read register
    q2_mem_read_gadgets = []
    for r in r32:
        q2_mem_read_gadgets_reg = q2_mem_read(gadget_list, r)
        append_result_file(filename, q2_mem_read_gadgets_reg[0:15], "15 shortest mem read for " + r + " ; ", aslr, dll_name, image_base)
        q2_mem_read_gadgets += q2_mem_read_gadgets_reg
    gadget_list = remove_gadgets_from_gadget_list(gadget_list, q2_mem_read_gadgets)

    
    return gadget_list


def main(srcfile, bad_bytes, aslr, dll_name, image_base):
    # convert to unix format
    result = subprocess.run(['dos2unix', srcfile], stdout=subprocess.PIPE)
    #print(result.stdout)

    file = srcfile # file to read gadgets from (rp++ output)

    # resultfile where filtered gadgets will be written
    resultfile_bc = file.strip(".txt") + ".bc-filtered.txt"
    resultfile_q1 = file.strip(".txt") + ".q1.txt"
    resultfile_q2 = file.strip(".txt") + ".q2.txt"

    gadget_list = read_gadgets_from_rp_file(file) # read gadgets into list
    
    # if bad chars as argument, remove addresses containing bad chars
    if bad_bytes:
        badchars = bad_bytes.strip("\\x") # string of bad characters in 0xff or ff format
        badchar_filtered_gadgets = filter_bad_char_gadgets(gadget_list, badchars, aslr) # filter out addresses with bad chars
        gadget_list = badchar_filtered_gadgets

    print("Number of valid gadgets found: " + str(len(gadget_list)))

    large_return_filtered_gadgets = filter_large_return_gadgets(gadget_list) # filter out gadgets with return >255
    gadgetcount = len(large_return_filtered_gadgets)
    print("Number of gadgets excluding retn >255 found: " + str(gadgetcount))

    # empty the destination files
    create_result_file(resultfile_bc)
    create_result_file(resultfile_q1)
    create_result_file(resultfile_q2)

    # append initially filtered gadgets to bc file in case we want to search manually later
    append_result_file(resultfile_bc, large_return_filtered_gadgets, "gadgets filtered for badchars and large returns", aslr, dll_name, image_base) # 

    # clean, short gadgets, sorted by usage
    q1_filtered_gadgets = q1(resultfile_q1, large_return_filtered_gadgets, aslr, dll_name, image_base) # extract highest-quality gadgets to separate file
    print("Gadgets remaining after Q1 (high quality) filtering: " + str(len(q1_filtered_gadgets)))

    # lesser quality gadgets
    q2_filtered_gadgets = q2(resultfile_q2, q1_filtered_gadgets, aslr, dll_name, image_base)
    print("Gadgets remaining after Q2 (medium quality) filtering: " + str(len(q2_filtered_gadgets)))

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Filter rp++ output for high-quality gadgets')
    parser.add_argument('srcfile',type=str, help='rp++ output file to ingest')
    parser.add_argument('--bad-bytes', type=str, help='string of bad characters, formatted as \"\\x00\\x0a\" or \"000a\"')
    parser.add_argument('--aslr', type=int, help='Specify the number of hex characters to disregard for bad bytes in case ASLR is used. Will also convert addresses to format similar to dllbase+0x0000 in q1 and q2 outputs.')
    parser.add_argument('--dll-name', type=str, help='change the name from dllbase to something else. Useful in case gadgets from multiple dlls are used.')
    parser.add_argument('--image-base', type=str, help='dllbase used in rp++. Can be calculated with find-imagebase.py. Use in combination with --aslr flag for accurate gadget offsets, ready to copy.')

    args = parser.parse_args()

    if args.aslr != None:
        if args.image_base == None:
            print("--image-base should be set when using --aslr flag.")
            exit()

    main(args.srcfile, args.bad_bytes, args.aslr, args.dll_name, args.image_base)
