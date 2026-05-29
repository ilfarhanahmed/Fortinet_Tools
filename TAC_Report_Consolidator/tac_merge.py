
print("TACMerge")
print("FortiManager/FortiAnalyzer GUI TAC report command-log merger")

filename = "6_get system status.log"
# print(filename[2:])

def remove_log_extension(filename):
    realname = filename[:-4]
    return realname

def remove_num_prefix(filename):
    parts = filename.split("_", 1)
    if len(parts) == 2:
        return parts[1]

    return filename

# ------
# MAIN
# -------
print(remove_log_extension(remove_num_prefix(filename)))