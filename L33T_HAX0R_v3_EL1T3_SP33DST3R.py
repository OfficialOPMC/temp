import pymem
import re
import time
import ctypes
import struct



class Exploit:
 def __init__(self,ProgramName=None):
  self.ProgramName = ProgramName
  self.Pymem = pymem.Pymem()
  self.Addresses = {}
  self.Handle = None
  self.is64bit = False
  self.ProcessID = None
  self.PID = self.ProcessID
  if type(ProgramName) == str:
   self.Pymem = pymem.Pymem(ProgramName)
   self.Handle = self.Pymem.process_handle
   self.is64bit = not pymem.process.is_64_bit(self.Handle)
   self.ProcessID = self.Pymem.process_id
   self.PID = self.ProcessID
  elif type(ProgramName) == int:
   self.Pymem.open_process_from_id(ProgramName)
   self.Handle = self.Pymem.process_handle
   self.is64bit = not pymem.process.is_64_bit(self.Handle)
   self.ProcessID = self.Pymem.process_id
   self.PID = self.ProcessID
 def h2d(self,hz:str,bit:int=16) -> int:
  if type(hz) == int:
   return hz
  return int(hz,bit)
 def d2h(self,dc:int,UseAuto=None) -> str:
  if type(dc) == str:
   return dc
  if UseAuto:
   if UseAuto == 32:
    dc = hex(dc & (2**32-1)).replace('0x','')
   else:
    dc = hex(dc & (2**64-1)).replace('0x','')
  else:
   if abs(dc) > 4294967295:
    dc = hex(dc & (2**64-1)).replace('0x','')
   else:
    dc = hex(dc & (2**32-1)).replace('0x','')
  if len(dc) > 8:
   while len(dc) < 16:
    dc = '0' + dc
  if len(dc) < 8:
   while len(dc) < 8:
    dc = '0' + dc
  return dc
 def PLAT(self,aob:str):
  if type(aob) == bytes:
   return aob
  trueB = bytearray(b'')
  aob = aob.replace(' ','')
  PLATlist = []
  for i in range(0,len(aob), 2):
   PLATlist.append(aob[i:i+2])
  for i in PLATlist:
   if "?" in i:
    trueB.extend(b'.')
   if "?" not in i:
    trueB.extend(re.escape(bytes.fromhex(i)))
  return bytes(trueB)
 def AOBSCANALL(self,AOB_HexArray,xreturn_multiple=False):
  return pymem.pattern.pattern_scan_all(self.Pymem.process_handle,self.PLAT(AOB_HexArray),return_multiple=xreturn_multiple)
 def gethexc(self,hex:str):
  hex = hex.replace(' ','')
  hxlist = []
  for i in range(0,len(hex), 2):
   hxlist.append(hex[i:i+2])
  return len(hxlist)
 def hex2le(self,hex:str):
  lehex = hex.replace(' ','')
  lelist = []
  if len(lehex) > 8:
   while len(lehex) < 16:
    lehex = '0' + lehex
   for i in range(0,len(lehex), 2):
    lelist.append(lehex[i:i+2])
   lelist.reverse()
   return ''.join(lelist)
  if len(lehex) < 9:
   while len(lehex) < 8:
    lehex = '0' + lehex
   for i in range(0,len(lehex), 2):
    lelist.append(lehex[i:i+2])
   lelist.reverse()
   return ''.join(lelist)
 def calcjmpop(self,des,cur):
  jmpopc = (self.h2d(des) - self.h2d(cur)) - 5
  jmpopc = hex(jmpopc & (2**32-1)).replace('0x','')
  if len(jmpopc) % 2 != 0:
   jmpopc = '0' + str(jmpopc)
  return jmpopc
 def isProgramGameActive(self):
  try:
   self.Pymem.read_char(self.Pymem.base_address)
   return True
  except:
   return False
 def DRP(self,Address:int,is64Bit:bool = None) -> int:
  Address = Address
  if type(Address) == str:
   Address = self.h2d(Address)
  if is64Bit:
   return int.from_bytes(self.Pymem.read_bytes(Address,8),'little')
  if self.is64bit:
   return int.from_bytes(self.Pymem.read_bytes(Address,8),'little')
  return int.from_bytes(self.Pymem.read_bytes(Address,4),'little')
 def isValidPointer(self,Address:int,is64Bit:bool = None) -> bool:
  try:
   if type(Address) == str:
    Address = self.h2d(Address)
   self.Pymem.read_bytes(self.DRP(Address,is64Bit),1)
   return True
  except:
   return False
 def GetModules(self) -> list:
  return list(self.Pymem.list_modules())
 def getAddressFromName(self,Address:str) -> int:
  if type(Address) == int:
   return Address
  AddressBase = 0
  AddressOffset = 0
  for i in self.GetModules():
   if i.name in Address:
    AddressBase = i.lpBaseOfDll
    AddressOffset = self.h2d(Address.replace(i.name + '+',''))
    AddressNamed = AddressBase + AddressOffset
    return AddressNamed
  print("Unable to find Address: " + Address)
  return Address
 def getNameFromAddress(self,Address:int) -> str:
  memoryInfo = pymem.memory.virtual_query(self.Pymem.process_handle,Address)
  BaseAddress = memoryInfo.BaseAddress
  NameOfDLL = ''
  AddressOffset = 0
  for i in self.GetModules():
   if i.lpBaseOfDll == BaseAddress:
    NameOfDLL = i.name
    AddressOffset = Address - BaseAddress
    break
  if NameOfDLL == '':
   return Address
  NameOfAddress = NameOfDLL + '+' + self.d2h(AddressOffset)
  return NameOfAddress
 def getRawProcesses(self):
  toreturn = []
  for i in pymem.process.list_processes():
   toreturn.append([i.cntThreads,i.cntUsage,i.dwFlags,i.dwSize,i.pcPriClassBase,i.szExeFile,i.th32DefaultHeapID,i.th32ModuleID,i.th32ParentProcessID,i.th32ProcessID])
  return toreturn
 def SimpleGetProcesses(self):
  toreturn = []
  for i in self.getRawProcesses():
   toreturn.append({"Name":i[5].decode(),"Threads":i[0],"ProcessId":i[9]})
  return toreturn
 def YieldForProgram(self,programName,AutoOpen:bool = False,Limit = 15):
  Count = 0
  while True:
   if Count > Limit:
    print("Yielded too long, failed!")
    return False
   ProcessesList = self.SimpleGetProcesses()
   for i in ProcessesList:
    if i['Name'] == programName:
     print("Found " + programName + " with Process ID: " + str(i['ProcessId']))
     if AutoOpen:
      self.Pymem.open_process_from_id(i['ProcessId'])
      self.ProgramName = programName
      self.Handle = self.Pymem.process_handle
      self.is64bit = not pymem.process.is_64_bit(self.Handle)
      self.ProcessID = self.Pymem.process_id
      self.PID = self.ProcessID
      print("Successfully attached to Process.")
     return True
   print("Waiting for the Program: " + programName)
   time.sleep(1)
   Count += 1
 def ReadPointer(self,BaseAddress:int,Offsets_L2R:list,is64Bit:bool = None) -> int:
  x = self.DRP(BaseAddress,is64Bit)
  y = Offsets_L2R
  z = x
  if y == None or len(y) == 0:
   return z
  count = 0
  for i in y:
   try:
    print(self.d2h(x + i))
    print(self.d2h(i))
    z = self.DRP(z + i,is64Bit)
    count += 1
    print(self.d2h(z))
   except:
    print('Failed to read Offset at Index: ' + str(count))
    return z
  return z
 def GetMemoryInfo(self,Address:int,Handle:int=None):
  if Handle:
   return pymem.memory.virtual_query(Handle,Address)
  else:
   return pymem.memory.virtual_query(self.Handle,Address)
 def MemoryInfoToDictionary(self,MemoryInfo):
  return {'BaseAddress':MemoryInfo.BaseAddress,'AllocationBase':MemoryInfo.AllocationBase,'AllocationProtect':MemoryInfo.AllocationProtect,'RegionSize':MemoryInfo.RegionSize,'State':MemoryInfo.State,'Protect':MemoryInfo.Protect,'Type':MemoryInfo.Type}
 def SetProtection(self,Address:int,ProtectionType = 0x40,Size:int = 4,OldProtect=ctypes.c_ulong(0)):
  pymem.ressources.kernel32.VirtualProtectEx(self.Pymem.process_handle,Address,Size,ProtectionType,ctypes.byref(OldProtect))
  return OldProtect
 def ChangeProtection(self,Address:int,ProtectionType = 0x40,Size:int = 4,OldProtect=ctypes.c_ulong(0)):
  return self.SetProtection(Address,ProtectionType,Size,OldProtect)
 def GetProtection(self,Address:int):
  return self.GetMemoryInfo(Address).Protect
 def KnowProtection(self,Protection):
  if Protection == 0x10:
   return "PAGE_EXECUTE"
  if Protection == 0x20:
   return "PAGE_EXECUTE_READ"
  if Protection == 0x40:
   return "PAGE_EXECUTE_READWRITE"
  if Protection == 0x80:
   return "PAGE_EXECUTE_WRITECOPY"
  if Protection == 0x01:
   return "PAGE_NOACCESS"
  if Protection == 0x02:
   return "PAGE_READONLY"
  if Protection == 0x04:
   return "PAGE_READWRITE"
  if Protection == 0x08:
   return "PAGE_WRITECOPY"
  if Protection == 0x100:
   return "PAGE_GUARD"
  if Protection == 0x200:
   return "PAGE_NOCACHE"
  if Protection == 0x400:
   return "PAGE_WRITECOMBINE"
  if Protection in ["PAGE_EXECUTE",'execute','e']:
   return 0x10
  if Protection in ["PAGE_EXECUTE_READ",'execute read','read execute','execute_read','read_execute','er','re']:
   return 0x20
  if Protection in ["PAGE_EXECUTE_READWRITE",'execute read write','execute write read','write execute read','write read execute','read write execute','read execute write','erw','ewr','wre','wer','rew','rwe']:
   return 0x40
  if Protection in ["PAGE_EXECUTE_WRITECOPY",'execute copy write','execute write copy','write execute copy','write copy execute','copy write execute','copy execute write','ecw','ewc','wce','wec','cew','cwe']:
   return 0x80
  if Protection in ["PAGE_NOACCESS",'noaccess','na','n']:
   return 0x01
  if Protection in ["PAGE_READONLY",'readonly','ro','r']:
   return 0x02
  if Protection in ["PAGE_READWRITE",'read write','write read','wr','rw']:
   return 0x04
  if Protection in ["PAGE_WRITECOPY",'write copy','copy write','wc','cw']:
   return 0x08
  if Protection in ["PAGE_GUARD",'pg','guard','g']:
   return 0x100
  if Protection in ["PAGE_NOCACHE",'nc','nocache']:
   return 0x200
  if Protection in ["PAGE_WRITECOMBINE",'write combine','combine write']:
   return 0x400
  return Protection
 def Suspend(self,pid:int = None):
  kernel32 = ctypes.WinDLL('kernel32.dll')
  if pid:
   kernel32.DebugActiveProcess(pid)
  if self.PID:
   kernel32.DebugActiveProcess(self.PID)
 def Resume(self,pid:int = None):
  kernel32 = ctypes.WinDLL('kernel32.dll')
  if pid:
   kernel32.DebugActiveProcessStop(pid)
  if self.PID:
   kernel32.DebugActiveProcessStop(self.PID)











def HAX0R_HAX(UNO):
 x = UNO
 y = ""
 z = []
 if len(x.split(' ')) > 1:
  for i in range(0,len(x)-1):
   if x[i] == " ":
    y = x[0]
    break
   y = y + x[i]
   if y not in x:
    y = y[:-1]
    break
 else:
  y = x[0]
 for i in x.split(' '):
  z.append(chr(i.count(y)))
 return "".join(z)


Hacker = Exploit()



Roblox = None
RobloxBaseModuleAddress = 0x40000000



def GET_ROBLOX_BASE():
 return RobloxBaseModuleAddress



#Addresses
W3B_R0BL0X_ADDR3SS = GET_ROBLOX_BASE() + 0x1337C0DE#GOTTA BE L33T HAX0R TO BYPASS! Latest Web/Desktop Version: version-3aba366803e44f0e



while True:
 Roblox = Hacker.YieldForProgram('RobloxPlayerBeta.exe',True,1)
 if Roblox:
  print("Attached to Desktop/Windows Roblox!")
  Roblox = 1
  break



Var1 = 0



def HAX0R_HACK_INTO_MAIN_FRAME():
 M = 3999
 A = 1325122
 I = 142728
 N = 425712
 F = 83727518
 R = 65628954187
 A = 10928499
 M = 69592819
 E = 2422989
 MAIN_FRAME = M + A + I + N + F + R + A + M + E
 return int(MAIN_FRAME+17/0xBADF00D)


def HAX0R_GET_ADMIN_ACCESS():
 CMD_PROMPT = 29301
 BATCH_CODE = 0x4B1D
 RUN_ON_CLICK = -2
 return CMD_PROMPT + BATCH_CODE + RUN_ON_CLICK


def GENERATE_HAX0R_CRYPTO():
 if True:
  pass
 if False:
  return 82382738174829158958219
 else:
  return 70316461641352



def BYFRON_BEGONE():
 return 5524832768



W3B_R0BL0X_ADDR3SS = int((GENERATE_HAX0R_CRYPTO()*2) + W3B_R0BL0X_ADDR3SS + HAX0R_HACK_INTO_MAIN_FRAME() + HAX0R_GET_ADMIN_ACCESS()) - BYFRON_BEGONE()





def GET_HAX0R_C0D3(JAVASCRIPT_INJECTOR_HAX_ISLOADED_AND_LOGGED):
 if Roblox:
  return W3B_R0BL0X_ADDR3SS+64
 else:
  return W3B_R0BL0X_ADDR3SS-32






IiiIiiiiIIIiII = ''

if Roblox:
 IiiIiiiiIIIiII = GET_HAX0R_C0D3(W3B_R0BL0X_ADDR3SS)*8
else:
 IiiIiiiiIIIiII = GET_HAX0R_C0D3(W3B_R0BL0X_ADDR3SS)/4





HumanoidVT1FunctionBytes=bytes.fromhex('b883e96303c3cccccccccccccccccccc4883ec28488b51504885d2747f4c')
HumanoidVT3FunctionBytes=bytes.fromhex('48895c24185556574883ec70498bf1498be8488bfa488bd9488379600074')
HumanoidVT4FunctionBytes=bytes.fromhex('32c0c3cccccccccccccccccccccccccc33c048c742180f00000048890248')
HumanoidVT5FunctionBytes=bytes.fromhex('4883ec28488b05f501ec034885c07510e8cbd5ffff488b4008488905e001')
HumanoidVT6FunctionBytes=bytes.fromhex('c20000cccccccccccccccccccccccccc33c0488902488942084889421048')

print("Scanning...")

ScanDataOfHumanoid1 = Hacker.AOBSCANALL(HumanoidVT1FunctionBytes.hex(),True)
ScanDataOfHumanoid3 = Hacker.AOBSCANALL(HumanoidVT3FunctionBytes.hex(),True)
ScanDataOfHumanoid4 = Hacker.AOBSCANALL(HumanoidVT4FunctionBytes.hex(),True)


XHumanoidVT1FunctionAddress = ScanDataOfHumanoid1[-1]
XHumanoidVT3FunctionAddress = ScanDataOfHumanoid3[-1]
XHumanoidVT4FunctionAddress = ScanDataOfHumanoid4[-1]


XHumanoidVT1ScanData = Hacker.AOBSCANALL(Hacker.hex2le(Hacker.d2h(XHumanoidVT1FunctionAddress)),True)


print(HAX0R_HAX('``````````````````````````````````````````````````````````````````````````````````` ``````````````````````````````````````````````````````````````````````````````````````````````````` ````````````````````````````````````````````````````````````````````````````````````````````````` `````````````````````````````````````````````````````````````````````````````````````````````````````````````` `````````````````````````````````````````````````````````````````````````````````````````````````````````````` ````````````````````````````````````````````````````````````````````````````````````````````````````````` `````````````````````````````````````````````````````````````````````````````````````````````````````````````` ``````````````````````````````````````````````````````````````````````````````````````````````````````` ```````````````````````````````` ````````````````````````````````````````````````````````````````````````````````````````````````````````` ``````````````````````````````````````````````````````````````````````````````````````````````````````````````````` ```````````````````````````````` ```````````````````````````````````````````````````````````````````````````````````````````````````` ``````````````````````````````````````````````````````````````````````````````````````````````````````````````` `````````````````````````````````````````````````````````````````````````````````````````````````````````````` ````````````````````````````````````````````````````````````````````````````````````````````````````` ````````````````````````````````` ```````````````````````````````` `````````````````````````````````````````````````````````````````````````````````````` ````````````````````````````````````````````````````````````````````````````````````````````````````` `````````````````````````````````````````````````````````````````````````````````````````````````````````````````` ````````````````````````````````````````````````````````````````````````````````````````````````````````` `````````````````````````````````````````````````````````````````````````````````````````````````````` ````````````````````````````````````````````````````````````````````````````````````````````````````````````````````````` ````````````````````````````````````````````````````````````````````````````````````````````````````````` `````````````````````````````````````````````````````````````````````````````````````````````````````````````` ``````````````````````````````````````````````````````````````````````````````````````````````````````` ```````````````````````````````` ````````````````````````````````````````````````````````````````````````````````````````````````````````` `````````````````````````````````````````````````````````````````````````````````````````````````````````````` ```````````````````````````````````````````````````````````````````````````````````````````````````````````````````` ````````````````````````````````````````````````````````````````````````````````````````````````````` ``````````````````````````````````````````````````````````````````````````````````````````````````````` `````````````````````````````````````````````````````````````````````````````````````````````````````````````````` ````````````````````````````````````````````````````````````````````````````````````````````````````````` ```````````````````````````````````````````````````````````````````````````````````````````````````````````````````` ````````````````````````````````````````````````````````````````````````````````````````````````````````````````````````` `````````````````````````````````````````````` `````````````````````````````````````````````` ``````````````````````````````````````````````'))


FilteredVTables = []
HumanoidVT = 0
for i in XHumanoidVT1ScanData:
 if (Hacker.isValidPointer(i+16)) and (Hacker.isValidPointer(i+24)) and (Hacker.isValidPointer(i+32)) and (Hacker.isValidPointer(i+40)):
  if Hacker.DRP(i+16) == XHumanoidVT3FunctionAddress and Hacker.DRP(i+24) == XHumanoidVT4FunctionAddress and Hacker.Pymem.read_bytes(Hacker.DRP(i+32),30).hex() == HumanoidVT5FunctionBytes.hex() and Hacker.Pymem.read_bytes(Hacker.DRP(i+40),30).hex() == HumanoidVT6FunctionBytes.hex():
   HumanoidVT = i
   FilteredVTables.append(i)


HumanoidVT = HumanoidVT - 8


ScanOfHumanoidsByVTable = Hacker.AOBSCANALL(Hacker.hex2le(Hacker.d2h(HumanoidVT)),True)


ClassName_Offset = 0xC


def isPointerToInstance(Instance:int) -> bool:
 if Hacker.isValidPointer(Instance,True):
  x = Hacker.DRP(Instance,True)
  if Hacker.isValidPointer(x,True) and Hacker.isValidPointer(x + ClassName_Offset,True) and Hacker.DRP(x + 8,True) == x:
   return True

def isInstanceValid(Instance:int) -> bool:
 if not Instance:
  return False
 if Instance == 0:
  return False
 if not Hacker.isValidPointer(Instance,True):
  return False
 if Hacker.Pymem.read_int(Instance) == 0:
  return False
 if not isPointerToInstance(Instance):
  x = Instance
  if not Hacker.isValidPointer(x,True) and not Hacker.isValidPointer(x + ClassName_Offset,True) and not Hacker.DRP(x + 8,True) == x:
   return False
 return True



WalkSpeedAddressOffset = 0x340



def ConvertToBit(Address:int,bit:int=32):
 if bit == 64:
  return Hacker.h2d(Hacker.d2h(Address,64))
 else:
  return Hacker.h2d(Hacker.d2h(Address,32))


def SetWalkSpeed(Humanoid:int,Value):
 WalkSpeedAddress = Humanoid + WalkSpeedAddressOffset
 ShadowWalkSpeedAddress = WalkSpeedAddress + 8
 WalkSpeedEncryptedAddress = Hacker.DRP(WalkSpeedAddress)
 ShadowWalkSpeedEncryptedAddress = Hacker.DRP(ShadowWalkSpeedAddress)
 WalkSpeedEncryptedValue = Hacker.Pymem.read_longlong(WalkSpeedEncryptedAddress)
 ShadowWalkSpeedEncryptedValue = Hacker.Pymem.read_longlong(ShadowWalkSpeedEncryptedAddress)
 ValueFromFloat = ConvertToBit(Hacker.h2d(struct.pack('!f',Value).hex()),64)
 EAX_Address = ConvertToBit(WalkSpeedEncryptedAddress,32)
 RAX_Value = WalkSpeedEncryptedValue
 Real_Speed_Raw = Hacker.d2h(ConvertToBit(EAX_Address-ValueFromFloat),64)
 DistanceFromChecker = ShadowWalkSpeedEncryptedValue - WalkSpeedEncryptedValue
 Shadow_EAX_Address = ConvertToBit(ShadowWalkSpeedEncryptedAddress,32)
 Shadow_RAX_Value = ShadowWalkSpeedEncryptedValue
 Shadow_Real_Speed_Raw = Hacker.d2h(ConvertToBit(ValueFromFloat^Shadow_EAX_Address),64)
 Hacker.Pymem.write_int(WalkSpeedEncryptedAddress,Hacker.h2d(Real_Speed_Raw))
 Hacker.Pymem.write_int(ShadowWalkSpeedEncryptedAddress,Hacker.h2d(Shadow_Real_Speed_Raw))
 return True

def GetWalkSpeed(Humanoid,GetShadowWalkSpeed = False):
 WalkSpeedAddress = Humanoid + WalkSpeedAddressOffset
 if GetShadowWalkSpeed:
  WalkSpeedAddress = WalkSpeedAddress + 8
 WalkSpeedEncryptedAddress = Hacker.DRP(WalkSpeedAddress)
 WalkSpeedEncryptedValue = Hacker.Pymem.read_longlong(WalkSpeedEncryptedAddress)
 EAX_Address = ConvertToBit(WalkSpeedEncryptedAddress,32)
 RAX_Value = WalkSpeedEncryptedValue
 Real_Speed_Raw = Hacker.d2h(ConvertToBit(EAX_Address-RAX_Value),64)
 RealWalkSpeed = struct.unpack('!f', bytes.fromhex(Real_Speed_Raw))[0]
 return RealWalkSpeed




New_WalkSpeed = int(input('Input your desired WalkSpeed:'))


if 0x1:
 try:
  for i in ScanOfHumanoidsByVTable:
   if isInstanceValid(i):
    SetWalkSpeed(i,New_WalkSpeed)
 except:
  print(HAX0R_HAX('IIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII IIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII IIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII IIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII IIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII IIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII IIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII IIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII IIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII IIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII IIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII IIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII IIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII IIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII IIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII IIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII IIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII IIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII IIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII IIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII IIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII IIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII IIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII IIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII IIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII IIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII IIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII IIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII IIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII IIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII IIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII IIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII IIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII IIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII IIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII IIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII IIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII IIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII IIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII IIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII IIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII IIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII IIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII IIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII IIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII IIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII IIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII IIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII IIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII IIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII IIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII IIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII IIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII IIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII IIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII IIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII IIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII IIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII IIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII IIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII IIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII IIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII IIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII IIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII'))
  input('Restart!!!')





print(HAX0R_HAX("lllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll lllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll lllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll lllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll lllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll lllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll lllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll lllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllll lllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllll lllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll lllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll lllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll lllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllll lllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllll") + Hacker.d2h(IiiIiiiiIIIiII).upper() + HAX0R_HAX("llllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll lllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll lllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll lllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll lllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll lllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllll lllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllll lllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll lllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll lllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll lllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll lllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll lllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll lllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll lllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll lllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllll lllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllll lllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll lllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll lllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll lllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllll lllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllll lllllllllllllllllllllllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll lllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll lllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllll lllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllll lllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll lllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll lllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll lllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll lllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllll lllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll lllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll lllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll lllllllllllllllllllllllllllllllll lllllllllllllllllllllllllllllllll lllllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll lllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll lllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllll lllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll lllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll lllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll lllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll lllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll lllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll lllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll lllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll lllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll lllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll lllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll lllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllll lllllllllllllllllllllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllllllllllllllllllll lllllllllllllllllllllllllllllllllllll lllllllllllllllllllllllllllllllll lllllllllllllllllllllllllllllllll lllllllllllllllllllllllllllllllll"))
input(HAX0R_HAX("llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll lllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll lllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll lllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllll lllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll lllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll lllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll lllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll lllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllll lllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll lllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll lllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll lllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll"))
input(HAX0R_HAX("lllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll lllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll lllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllll lllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllll lllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll lllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll lllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll lllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll lllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll lllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll lllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll lllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll lllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll lllllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll lllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll lllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll lllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllll lllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll lllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll lllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll lllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll lllllllllllllllllllllllllllllllll"))
input(HAX0R_HAX("lllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllll lllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll lllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll lllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll lllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll lllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll lllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll lllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllll lllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll lllllllllllllllllllllllllllllllllllllll lllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllll lllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll lllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll lllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll lllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll lllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllll lllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll lllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll lllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll lllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll lllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll lllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllll lllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll lllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll lllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll lllllllllllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllll lllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll lllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll lllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll lllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll lllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllll lllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll lllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll lllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll lllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllll lllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll lllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll lllllllllllllllllllllllllllllllll lllllllllllllllllllllllllllllllll lllllllllllllllllllllllllllllllll lllllllllllllllllllllllllllllllll lllllllllllllllllllllllllllllllll lllllllllllllllllllllllllllllllll lllllllllllllllllllllllllllllllll"))


def HAX0R_L0G_DATA(DDOS):
 toreturn = []
 if ' ' not in DDOS:
  return chr(Hacker.h2d(DDOS))
 for i in DDOS.split(' '):
  toreturn.append(chr(Hacker.h2d(i)))
 return "".join(toreturn)


input(HAX0R_L0G_DATA('0000002A 00000045 00000041 00000054 00000053 00000020 00000043 0000004F 0000004F 0000004B 00000049 00000045 00000053 0000002A'))
input("Exiting...")











