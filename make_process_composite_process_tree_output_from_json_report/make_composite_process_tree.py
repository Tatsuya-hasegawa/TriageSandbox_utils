#!/usr/bin/env python

def appendfamily_sig(resultTree,signatures):
    for sig in signatures:
        if "indicators" in sig:
            hitFlag = False
            for indicator in sig["indicators"]:
                if "yara_rule" in indicator:
                    if not hitFlag:
                        i = 0
                        while i < len(resultTree):
                            if str(resultTree[i]['PID']) == indicator["resource"].split("/")[-1].split("-")[0]:
                                #print(resultTree[i]['PID'],sig)
                                resultTree[i]['Family (yara)'].append(sig["name"]+" (signature)")
                                hitFlag = True
                            i+=1
    return resultTree


def appendfamily_extracted(resultTree,extracted):
    for extra in extracted:
        if "dumped_file" in extra:
            i = 0
            while i < len(resultTree):
                if str(resultTree[i]['PID']) == extra["dumped_file"].split("/")[-1].split("-")[0]:
                    #print(resultTree[i]['PID'],extra)
                    resultTree[i]['Family (yara)'].append(extra["config"]["rule"]+" (extracted)")
                i+=1
    return resultTree


def appendhash(resultTree,dumped):
    for payload in dumped:
        if "path" in payload:
            if "sha256" in payload:
                i = 0
                while i < len(resultTree):
                    if resultTree[i]['PID'] == payload["pid"]:
                        if resultTree[i]['Image'] == payload["path"]:
                            #print(resultTree[i]['Image'],payload["path"])
                            resultTree[i]['ProcessImage SHA256 (dumped)'] = payload["sha256"]
                    i+=1                
    return resultTree

def appendnetwork(resultTree,network):
    for flow in network.get("flows"):
        if "pid" in flow:
            i = 0
            while i < len(resultTree):
                if resultTree[i]['PID'] == flow["pid"]:
                    #print(resultTree[i]['PID'],flow)
                    resultTree[i]['NetworkFlow'] = "{} ({})".format(flow["dst"],flow.get(domain))
                i+=1   
    return resultTree


def maketree(orig_processes):
    import copy
    processes = sorted(orig_processes, key=lambda x: x['started'])
    processes_copy = copy.deepcopy(processes)

    tmpTree = []
    max_depth = 0
    firstFlag = True
    i = 0
    for i in range(0,len(processes)):
        j = 0
        while j < len(processes):
            if not "procid_parent" in processes[j] or firstFlag: # root process
                if processes[j]["image"] in processes[j]["cmd"]: cmd = "{}{}".format("|",processes[j]["cmd"])
                else: cmd = "{}{} {}".format("|",processes[j]["image"],processes[j]["cmd"])
                
                tmpTree.append({"cmd":cmd, "depth":0, "procid":processes[j]['procid'], "pid":processes[j]["pid"], "ppid":processes[j]["ppid"], "image":processes[j]["image"]})
                prev_procid = processes[j]['procid']
                del processes[j]
                j -= 1
                firstFlag = False
                break
            elif processes[j]["procid_parent"] == prev_procid: # process that parent id is the previous process entry
                t_depth = 0
                for ele in tmpTree:
                    if ele['procid'] == prev_procid:
                        t_depth = ele['depth']
                
                if processes[j]["image"] in processes[j]["cmd"]: cmd = "{}{}".format("|   "*(t_depth+1)+"|____",processes[j]["cmd"])
                else: cmd = "{}{} {}".format("|   "*(t_depth+1)+"|____",processes[j]["image"],processes[j]["cmd"])
                
                if t_depth+1 > max_depth:
                    max_depth = t_depth + 1
                
                tmpTree.append({"cmd":cmd, "depth":t_depth+1, "procid":processes[j]['procid'], "pid":processes[j]["pid"], "ppid":processes[j]["ppid"], "image":processes[j]["image"]})
                del processes[j]
                j -= 1                
            j+=1
        
        if i!=0: 
            try: prev_procid = processes_copy[i]["procid_parent"]
            except KeyError: pass

        i+=1


    resultTree = []
    t_depth = 0
    rootFlag = True
    prev_pid = 0
    alreadys = []
    #debugline = 8
    for ele in tmpTree:
        alreadyFlag = False
        if prev_pid != ele['ppid']: 
            newbranchFlag = True

        if ele["pid"] in alreadys:
            alreadyFlag = True

        if not alreadyFlag:        
            for d in range(0,max_depth+1):
                if rootFlag:
                    resultTree.append({"ProcessDepth": ele["depth"],"ProcessTree":ele["cmd"], "PID":ele["pid"], "PPID":ele["ppid"], 'Family (yara)': [], "Image":ele["image"], 'ProcessImage SHA256 (dumped)': None })
                    alreadys.append(ele["pid"])
                    prev_pid = ele["pid"]
                    rootFlag = False
                    break
                else:
                    for d_ele in tmpTree: # deep scan to child process
                        if d == d_ele["depth"]:
                            if prev_pid == d_ele["ppid"] or ( newbranchFlag and not d_ele["pid"] in alreadys ):
                                k = 0
                                insertedFlag = False # whether new entry of child process
                                multichildFlag = False # whether the process has multi child processes on parallel
                                deeperchildFlag = False # whether more deeper child processes tied to the preivous child process
                                n = 0
                                #print(len(resultTree),d_ele)
                                while k < len(resultTree):
                                    #if len(resultTree)<=debugline: print("\t",resultTree[k]['PPID'] == d_ele["ppid"],resultTree[k]['ProcessDepth'] == d_ele["depth"],multichildFlag,resultTree[k]['ProcessDepth'] > d_ele["depth"],k,len(resultTree),resultTree[k]['PID'],resultTree[k]['PPID'],resultTree[k]['ProcessTree'])
                                    if resultTree[k]['PPID'] == d_ele["ppid"] and resultTree[k]['ProcessDepth'] == d_ele["depth"]: # parallel child processes
                                        if multichildFlag:
                                            n += 1
                                        else:
                                            n = k + 1
                                        multichildFlag = True
                                        deeperchildFlag = True
                                        #if len(resultTree)<=debugline: print("\t","---- parallel pass",n)
                                    elif multichildFlag and resultTree[k]['ProcessDepth'] > d_ele["depth"]: # deeper child process of parallel child processes
                                        if deeperchildFlag:
                                            #if len(resultTree)<=debugline: print("\t","++++ deeper pass",n)
                                            n += 1
                                        else:
                                            pass
                                    elif resultTree[k]['PID'] == d_ele["ppid"]:
                                        #if len(resultTree)<=debugline:print("\t","new child")
                                        insertedFlag = True
                                        multichildFlag = False
                                        n = k  
                                    elif resultTree[k]['ProcessDepth'] <= d_ele["depth"]:
                                        #if len(resultTree)<=debugline:print("\t","kill tie")
                                        deeperchildFlag = False

                                    k+=1

                                #if len(resultTree)<=debugline: 
                                #    if d==1 or n!=0: print("\t","depth",d,"inserted",n)
                                #    else: print("\t","depth",d,"inserted",n+1)

                                if multichildFlag:
                                    resultTree.insert(n,{"ProcessDepth": d_ele["depth"],"ProcessTree":d_ele["cmd"], "PID":d_ele["pid"], "PPID":d_ele["ppid"], 'Family (yara)': [], "Image": d_ele["image"], 'ProcessImage SHA256 (dumped)': None})                                  
                                elif insertedFlag:
                                    resultTree.insert(n+1,{"ProcessDepth": d_ele["depth"],"ProcessTree":d_ele["cmd"], "PID":d_ele["pid"], "PPID":d_ele["ppid"], 'Family (yara)': [], "Image": d_ele["image"], 'ProcessImage SHA256 (dumped)': None})
                                else:
                                    resultTree.append({"ProcessDepth": d_ele["depth"],"ProcessTree":d_ele["cmd"], "PID":d_ele["pid"], "PPID":d_ele["ppid"], 'Family (yara)': [], "Image": d_ele["image"], 'ProcessImage SHA256 (dumped)': None})

                                alreadys.append(d_ele["pid"])  
                                prev_pid = d_ele["pid"]
                                newbranchFlag = False
            prev_pid = ele["pid"]
            

    finalTree = []
    numId = 1
    for result in resultTree:
        #print("{:02} {:04} {:04} {}".format(numId,result["PID"],result["PPID"],result["ProcessTree"]))
        result["numId"] = numId
        finalTree.append(result)
        numId += 1

    return finalTree





if __name__ == "__main__":
    import sys
    import json
    from pygments import highlight
    from pygments.lexers import JsonLexer
    from pygments.formatters import TerminalFormatter

    input_file = sys.argv[1]
    print(f"INPUT JSON FILE: {input_file}")
    with open(input_file,"r") as jsonfile:
        jsonraw = json.load(jsonfile)

    formatted_data = json.dumps(sorted(jsonraw['processes'], key=lambda x: x['started']), indent=2)
    print(highlight(formatted_data, JsonLexer(), TerminalFormatter()))

    print("=========== make process tree ==============")
    resultTree = maketree(jsonraw.get('processes'))
    print("done!")

    print("========== append malware family ==========")
    resultTree = appendfamily_sig(resultTree,jsonraw.get('signatures'))
    resultTree = appendfamily_extracted(resultTree,jsonraw.get('extracted'))
    print("done!")

    print("========== append hash ==========")
    resultTree = appendhash(resultTree,jsonraw['dumped'])
    print("done!")

    print("========== append network ==========")
    resultTree = appendnetwork(resultTree,jsonraw['network'])
    print("done!")

    print("========== show composite process tree ==========")
    formatted_data = json.dumps(resultTree, indent=2)
    print(highlight(formatted_data, JsonLexer(), TerminalFormatter()))
    print("\ncompleted!")


    print("========== (Optional) show by pandas data frame ==========")
    import pandas as pd
    df = pd.json_normalize(resultTree,)
    print(df)
