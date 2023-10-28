import os
import time
import ctypes
from pymem import Pymem, process

print("Roblox TEST-UWP Walkspeed Changer")
print("Made by arbeit_macht_frei.")
print("\n")
input("Press Enter! ")

for i in range(50):
    print("Byfron is Trash LOL")
    time.sleep(0.01)

time.sleep(0.1)

os.system("cls")

max_retries = 100 
retry_interval = 0.1 
retry_count = 0

while retry_count < max_retries:
    try:
        mem = Pymem("Windows10Universal.exe")
        break
    except Exception:
        retry_count += 1
        time.sleep(retry_interval)
        print("Roblox UWP not Found!")
else:
    print("Prozess wurde nicht gefunden nach {0} Wiederholungen.".format(max_retries))

mem = Pymem("Windows10Universal.exe")

if mem:
    print("Process Found! (Windows10Universal.exe)")

game_module = process.module_from_name(mem.process_handle, "Windows10Universal.exe").lpBaseOfDll

def ChangeGravity(NewGravityValue):
    try:
        def getPtrAddr(address, offsets):
            addr = mem.read_int(address)
            for offset in offsets:
                if offset != offsets[-1]:
                    try:
                        addr = mem.read_int(addr + offset)
                    except Exception as e:
                        print(f"Error reading memory: {e}")
                        return None
            return addr + offsets[-1]

        target_address = getPtrAddr(game_module + 0x03725888, [0x8, 0x28, 0x28, 0xD4, 0x30, 0x20, 0xA0])
        print(target_address)
        if target_address is not None:
            print("Old Gravity:",mem.read_float(target_address))
            mem.write_float(target_address, NewGravityValue)
            print("New Gravity:",mem.read_float(target_address))

            time.sleep(1)
            
            os.system("cls")

            return mem.read_float(target_address)
        else:
            print("Failed to calculate the target address.")
    except Exception as e:
        print(f"Error: {e}")




while True:
    NewGrav = input("Enter new Gravity: ")
    ChangeGravity(float(NewGrav))