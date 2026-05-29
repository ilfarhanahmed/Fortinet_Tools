
print("TACMerge")
print("FortiManager/FortiAnalyzer GUI TAC report command-log merger")
print("============================")

filename = "6_get system status.log"
# print(filename[2:])

def command_name_from_filename(filename):
    realname = filename[:-4]  # GUI TAC report files are always ending on .log, hence -4 will work.
    command_name = realname.split("_", 1) # splitting the initial number part from filename.
    return command_name[1] # that is the second part of split which is the command.


# ------
# MAIN
# -------
print(command_name_from_filename(filename))