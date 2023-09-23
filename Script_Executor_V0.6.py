import pymem
import re
import time
import ctypes
import os
import requests
import tkinter as tk
from tkinter import scrolledtext




#These will need to be updated to work
DownloadCompiler = True#Download Epix's Compiler. Set to false if you don't wanna download exe files. You can't use rloadstring without it.
TaskSchedulerAddress = 'Windows10Universal.exe+359C3D4'
TextBoxCharacterLimit = 'Windows10Universal.exe+2F39154'
LuaVMLoadFunctionAddress = 'Windows10Universal.exe+554E90'#Thanks to YT (UserId: 1073140472639406080) for spoon feeding me the addresses and teaching how to find them LOL
GetStateFunctionAddress = 'Windows10Universal.exe+4555F0'
Task_Defer_FunctionAddress = 'Windows10Universal.exe+554030'#Actually Spawn, not Defer
Lua_Top = 0xC
Name_Offset = 0x2C
Character_Offset = 0x84
RobloxExtraSpace_Offset = 0x48
Identity_Offset = 0x18
UserId_Offset = 0x118




class Exploit:
 def __init__(self,ProgramName=None):
  self.ProgramName = ProgramName
  self.Pymem = pymem.Pymem()
  self.Addresses = {}
  if type(ProgramName) == str:
   self.Pymem = pymem.Pymem(ProgramName)
  elif type(ProgramName) == int:
   self.Pymem.open_process_from_id(ProgramName)
 def h2d(self,hz:str) -> int:
  if type(hz) == int:
   return hz
  return int(hz,16)
 def d2h(self,dc:int) -> str:
  if type(dc) == str:
   return dc
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
  if type(hex) == int:
   hex = self.d2h(hex)
  lehex = hex.replace(' ','')
  reniL = 0
  zqSij = ''
  lelist = []
  for i in range(0,len(lehex), 2):
   lelist.append(lehex[i:i+2])
  if len(lelist) != 4:
   reniL = len(lelist) - 4
   zqSij = zqSij + '0'
   for i in range(0,reniL):
    zqSij = zqSij + '00'
  lelist.insert(0,zqSij)
  if len(''.join(lelist)) != 8:
   lelist.insert(0,"0")
  lelist.reverse()
  lehex = ''.join(lelist)
  return lehex
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
 def DRP(self,Address:int,is64Bit:bool = False) -> int:
  Address = Address
  if type(Address) == str:
   Address = self.h2d(Address)
  if is64Bit:
   return int.from_bytes(self.Pymem.read_bytes(Address,8),'little')
  return int.from_bytes(self.Pymem.read_bytes(Address,4),'little')
 def isValidPointer(self,Address:int,is64Bit:bool = False) -> bool:
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
  AllocationBase = memoryInfo.AllocationBase
  NameOfDLL = ''
  AddressOffset = 0
  for i in self.GetModules():
   if i.lpBaseOfDll == AllocationBase:
    NameOfDLL = i.name
    AddressOffset = Address - AllocationBase
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
      print("Successfully attached to Process.")
     return True
   print("Waiting for the Program: " + programName)
   time.sleep(1)
   Count += 1
 def ReadPointer(self,BaseAddress:int,Offsets_L2R:list,is64Bit:bool = False) -> int:
  x = self.DRP(BaseAddress,is64Bit)
  y = Offsets_L2R
  z = x
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
 def ChangeProtection(self,Address:int,ProtectionType = 0x40,Size:int = 4,OldProtect=ctypes.c_ulong(0)):
  pymem.ressources.kernel32.VirtualProtectEx(self.Pymem.process_handle,Address,Size,ProtectionType,ctypes.byref(OldProtect))
  return OldProtect


def xyzStringToHex(text:str,noZeros = False) -> str:
 toreturn = []
 for i in text:
  toreturn.append(Exploit().d2h(ord(i)))
  toreturn.append(" ")
 toreturn = "".join(toreturn)[:-1].upper()
 if noZeros:
  aList = []
  for i in toreturn.split(' '):
   for ii in range(0,len(i)-1):
    if i[ii] != '0':
     aList.append(i[ii:])
     break
  toreturn = " ".join(aList).upper()
 return toreturn

def xyzHexToString(hex:str) -> str:
 toreturn = []
 if ' ' not in hex:
  return chr(Exploit().h2d(hex))
 for i in hex.split(' '):
  toreturn.append(chr(xyzh2d(i)))
 return "".join(toreturn)






Hacker = Exploit()
Hacker.YieldForProgram('Windows10Universal.exe',True)



def ReadRobloxString(ExpectedAddress:int) -> str:
 StringCount = Hacker.Pymem.read_int(ExpectedAddress + 0x10)
 if StringCount > 15:
  return Hacker.Pymem.read_string(Hacker.DRP(ExpectedAddress),StringCount)
 return Hacker.Pymem.read_string(ExpectedAddress,StringCount)


def GetTaskScheduler() -> int:
 return Hacker.getAddressFromName(TaskSchedulerAddress)

def isValidTask(TaskInstanceAddress:int) -> bool:
 x = TaskInstanceAddress
 if not Hacker.isValidPointer(x):
  return False
 y = Hacker.DRP(x)
 a = y
 b = a + 0x8
 c = a + 0xC
 if Hacker.DRP(b) == a and Hacker.isValidPointer(a) and Hacker.isValidPointer(c):
  return True

def GetTaskName(TaskInstanceAddress:int) -> str:
 x = TaskInstanceAddress
 if not Hacker.isValidPointer(x):
  return False
 y = Hacker.DRP(x)
 z = y + 0x80
 return ReadRobloxString(z)

def TaskSchedulerGetJobs() -> list:
 DynamicTaskScheduler = Hacker.DRP(GetTaskScheduler())
 JobStart = 0x134
 JobEnd = 0x138
 OffsetsPerJob = 8
 CurrentJob = Hacker.DRP(DynamicTaskScheduler + JobStart)
 JobEndAddress = Hacker.DRP(DynamicTaskScheduler + JobEnd)
 Jobs = []
 for i in range(0,1000):
  if i==999:
   print("Warning, there may be an issue with getting TaskScheduler jobs!")
  if CurrentJob == JobEndAddress:
   break
  Jobs.append(CurrentJob)
  CurrentJob += OffsetsPerJob
 return Jobs

def TaskSchedulerFindFirstJob(JobName:str) -> int:
 Jobs = TaskSchedulerGetJobs()
 for i in Jobs:
  if GetTaskName(i) == JobName:
   return i

def GetFPS() -> float:
 return 1/Hacker.read_double(Hacker.DRP(GetTaskScheduler())+0x118)

def SetFPS(FPSCount:float):
 Hacker.write_double(Hacker.DRP(GetTaskScheduler())+0x118,1/float(FPSCount))

def isTaskSchedulerAddress(Address,isDynamic=False):
 CurrentAddress = Address
 if Hacker.isValidPointer(CurrentAddress) or isDynamic:
  TaskScheduler = CurrentAddress
  DynamicTaskScheduler = None
  if isDynamic:
   DynamicTaskScheduler = TaskScheduler
  else:
   DynamicTaskScheduler = Hacker.DRP(TaskScheduler)
  JobStart = DynamicTaskScheduler + 0x134
  JobEnd = DynamicTaskScheduler + 0x138
  PointerX = DynamicTaskScheduler + 0x130
  PointerY = DynamicTaskScheduler + 0x13C
  if Hacker.isValidPointer(JobStart) and Hacker.isValidPointer(JobEnd) and Hacker.isValidPointer(PointerX) and Hacker.isValidPointer(PointerY):
   FirstJob = Hacker.DRP(JobStart)
   if Hacker.isValidPointer(FirstJob):
    if Hacker.DRP(Hacker.DRP(FirstJob)+8)==Hacker.DRP(FirstJob):
     if Hacker.Pymem.read_double(DynamicTaskScheduler + 0x8) == 0.05:
      return True



if not isTaskSchedulerAddress(GetTaskScheduler()):
 print('Task Scheduler is not valid. This means that Roblox has updated and you are using an outdated version or it means that you are not using the latest version of Roblox. Seek help!')
 time.sleep(10)
 exit()



def GetDataModelFromNetPeerSend() -> int:
 NPS = TaskSchedulerFindFirstJob("Net Peer Send")
 if not NPS:
  print('Unable to load Exploit because not in a game. Join a Roblox game first and then retry.')
  time.sleep(5)
  return None
 return Hacker.DRP(Hacker.DRP(NPS)+0x98)-8+0xA8


while True:
 if GetDataModelFromNetPeerSend():
  break
 input('Press anything when you are loaded in a game to retry.')


ClassName_Offset = 0xC


def GetDataModelAddress() -> int:
  return GetDataModelFromNetPeerSend()

def GetDataModel() -> int:
  return GetDataModelAddress() + 4



Children_Offset = Name_Offset + 0x4
Parent_Offset = Children_Offset + 0x8




def isPointerToInstance(Instance:int) -> bool:
 if Hacker.isValidPointer(Instance):
  x = Hacker.DRP(Instance)
  if Hacker.isValidPointer(x) and Hacker.isValidPointer(x + ClassName_Offset) and Hacker.DRP(x + 4) == x:
   return True

def isInstanceValid(Instance:int) -> bool:
 if not Instance:
  return False
 if Instance == 0:
  return False
 if not Hacker.isValidPointer(Instance):
  return False
 if Hacker.DRP(Instance) == 0:
  return False
 if not isPointerToInstance(Instance):
  x = Instance
  if not Hacker.isValidPointer(x) and not Hacker.isValidPointer(x + ClassName_Offset) and not Hacker.DRP(x + 4) == x:
   return False
 return True

def isValidDataModel(Address):
 if isInstanceValid(Address) and GetName(Address) == 'Game' and GetClassName(Address) == 'DataModel' and GetChildren(Address):
  if len(GetChildren(Address)) > 0:
   return True

def GetInstanceAddress(Instance:int) -> int:
 if not isInstanceValid(Instance):
  return False
 if isPointerToInstance(Instance):
  return Hacker.DRP(Instance)
 return Instance

def GetName(Instance:int) -> str:
 if not isInstanceValid(Instance):
  return False
 ExpectedAddress = Hacker.DRP(GetInstanceAddress(Instance) + Name_Offset)
 return ReadRobloxString(ExpectedAddress)

def GetClassDescriptor(Instance:int) -> int:
 if not isInstanceValid(Instance):
  return False
 ClassDescriptor = Hacker.DRP(GetInstanceAddress(Instance) + ClassName_Offset)
 if not Hacker.isValidPointer(ClassDescriptor):
  return False
 return ClassDescriptor

def GetClassName(Instance:int) -> str:
 ClassDescriptor = GetClassDescriptor(Instance)
 if not ClassDescriptor:
  return False
 ExpectedAddress = Hacker.DRP(ClassDescriptor + 4)
 return ReadRobloxString(ExpectedAddress)

def GetChildren(Instance:int) -> str:
 ChildrenInstance = []
 if not isInstanceValid(Instance):
  print("Invalid Instance to use GetChildren on!")
  return False
 InstanceAddress = GetInstanceAddress(Instance)
 if not InstanceAddress:
  return False
 ChildrenStart = Hacker.DRP(InstanceAddress + Children_Offset)
 if ChildrenStart == 0:
  return []
 ChildrenEnd = Hacker.DRP(ChildrenStart + 4)
 OffsetAddressPerChild = 0x8
 CurrentChildAddress = Hacker.DRP(ChildrenStart)
 for i in range(0,9000):
  if i==8999:
   print("Warning, there's too many Child, could be invalid!")
  if CurrentChildAddress == ChildrenEnd:
   break
  if isInstanceValid(CurrentChildAddress):
   ChildrenInstance.append(GetInstanceAddress(CurrentChildAddress))
  CurrentChildAddress += OffsetAddressPerChild
 return ChildrenInstance

def GetDescendants(Instance:int) -> list:
 DescendantChildren = []
 def LoopThroughChildren(InstanceChild):
  ChildrenInstances = GetChildren(InstanceChild)
  if len(ChildrenInstances) > 0:
   for i in ChildrenInstances:
    if isInstanceValid(i):
     DescendantChildren.append(i)
     LoopThroughChildren(i)
 LoopThroughChildren(Instance)
 return DescendantChildren

def FindFirstDescendant(Instance:int,Name:str) -> int:
 def LoopThroughChildren(InstanceChild):
  ChildrenInstances = GetChildren(InstanceChild)
  if len(ChildrenInstances) > 0:
   for i in ChildrenInstances:
    if isInstanceValid(i):
     if GetName(i) == Name:
      return i
     else:
      LoopThroughChildren(i)
 return LoopThroughChildren(Instance)

def FindFirstDescendantOfClass(Instance:int,ClassName:str) -> int:
 def LoopThroughChildren(InstanceChild):
  ChildrenInstances = GetChildren(InstanceChild)
  if len(ChildrenInstances) > 0:
   for i in ChildrenInstances:
    if isInstanceValid(i):
     if GetClassName(i) == Name:
      return i
     else:
      LoopThroughChildren(i)
 return LoopThroughChildren(Instance)

def GetService(ServiceName:str) -> int:
 ChildrenOfDataModel = GetChildren(GetDataModelAddress())
 if not ChildrenOfDataModel:
  return None
 for i in ChildrenOfDataModel:
  if GetClassName(i) == ServiceName:
   return i

def FindFirstChild(Instance:int,ChildName:str,Recursive:bool=False) -> int:
 ChildrenOfInstance = GetChildren(Instance)
 for i in ChildrenOfInstance:
  if GetName(i) == ChildName:
   return i
 if Recursive:
  return FindFirstDescendant(Instance,ChildName)

def FindFirstChildOfClass(Instance:int,ClassName:str,Recursive:bool=False) -> int:
 ChildrenOfInstance = GetChildren(Instance)
 for i in ChildrenOfInstance:
  if GetClassName(i) == ClassName:
   return i
 if Recursive:
  return FindFirstDescendantOfClass(Instance,ChildName)

def GetParent(Instance:int) -> int:
 if not isInstanceValid(Instance):
  return False
 return Hacker.DRP(GetInstanceAddress(Instance) + Parent_Offset)

def GetFullName(Instance:int):
 if Instance == GetDataModelAddress():
  return GetName(GetDataModelAddress())
 x = GetInstanceAddress(Instance)
 if not x:
  return False
 y = GetParent(Instance)
 z = ""
 ListOfDir = []
 LineName = ""
 currentParent = y
 IsDone = False
 Services = GetChildren(GetDataModelAddress())
 ListOfDir.append(GetName(x))
 for i in range(0,100):
  if i==99:
   print("Warning, DIR is too long, an error could exist")
  for ii in Services:
   if currentParent == GetInstanceAddress(ii):
    ListOfDir.append(GetName(currentParent))
    IsDone = True
    break
  if IsDone:
   break
  ListOfDir.append(GetName(currentParent))
  currentParent = GetParent(currentParent)
 ListOfDir.reverse()
 for i in ListOfDir:
  LineName = LineName + '.' + i
 return 'game'+LineName

def GetLocalPlayer() -> int:
 return FindFirstChildOfClass(GetService("Players"),"Player")

def GetPlayers() -> list:
 PlayerInstances = []
 PlayersChildren = GetChildren(GetService('Players'))
 for i in PlayersChildren:
  if GetClassName(i) == 'Player':
   PlayerInstances.append(i)
 return PlayerInstances

def GetOtherPlayers() -> list:
 Players = GetPlayers()
 Players.pop(0)
 return Players

def GetPlayer(PlayerName:str) -> int:
 for i in GetOtherPlayers():
  if GetName(i).lower() == PlayerName.lower():
   return i

def GetCharacter(Player:int) -> int:
 if not GetClassName(Player) == 'Player':
  return None
 return Hacker.DRP(GetInstanceAddress(Player) + Character_Offset)

def GetUserId(Player:int) -> int:
 if not GetClassName(Player) == 'Player':
  return None
 return Hacker.Pymem.read_ulonglong(GetInstanceAddress(Player) + UserId_Offset)

def IsA(Instance:int,ClassName):
 if GetClassName(Instance) == ClassName:
  return True

def WaitForChild(Instance:int,Child:str,Timeout:int=1):
 for i in range(Timeout):
  if FindFirstChild(Instance,Child):
   return FindFirstChild(Instance,Child)
  time.sleep(1)

def wait(Seconds):
 time.sleep(Seconds)








def PartCheck(Instance:int) -> bool:
 ClassName = GetClassName(Instance)
 if ClassName == "Part" or ClassName == "BasePart" or ClassName == "MeshPart" or ClassName == "UnionOperation" or ClassName == "Seat":
  return true


print("Welcome! " + GetName(GetLocalPlayer()) + ", thanks for trying it out!")






Hacker.Pymem.write_int(Hacker.getAddressFromName(TextBoxCharacterLimit),999999999)


StoredByteCodes = dict()


def GetStoredByteCode(HexStringByteCode:str) -> int:
 return StoredByteCodes.get(HexStringByteCode)

def MakeByteCodeAddress(HexStringByteCode:str) -> int:
 RawHexString = HexStringByteCode.replace(' ','')
 ByteCodeAddress = GetStoredByteCode(RawHexString)
 if ByteCodeAddress:
  return ByteCodeAddress
 print("Making New Memory in MakeByteCodeAddress function")
 ByteCodeAddress = Hacker.Pymem.allocate(50)
 Length = Hacker.gethexc(RawHexString)
 ByteCodeString = Hacker.Pymem.allocate(len(RawHexString) + 20)
 Hacker.Pymem.write_int(ByteCodeAddress,ByteCodeString)
 Hacker.Pymem.write_int(ByteCodeAddress + 0x10,Length)
 Hacker.Pymem.write_int(ByteCodeAddress + 0x14,Length + 20)
 Hacker.Pymem.write_bytes(ByteCodeString,bytes.fromhex(RawHexString),Length)
 StoredByteCodes.update({RawHexString:ByteCodeAddress})
 return ByteCodeAddress

def GetByteCodeAddress(Script:int) -> int:
 ClassName = GetClassName(Script)
 if ClassName == 'LocalScript':
  return Hacker.DRP(Script + 0x140) + 0x10
 if ClassName == 'ModuleScript':
  return Hacker.DRP(Script + 0x124) + 0x10
 print("Invalid support for Class: " + str(ClassName))

def GetByteCode(ByteCodeAddress:int) -> str:
 Length = Hacker.Pymem.read_int(ByteCodeAddress + 0x10)
 ByteCode = Hacker.Pymem.read_bytes(Hacker.DRP(ByteCodeAddress),Length).hex()
 return ByteCode



StoredOScripts = dict()



def GetStoredOScripts(ByteCodeAddress:int) -> int:
 return StoredOScripts.get(ByteCodeAddress)

def OverwriteByteCode(Script:int,ByteCodeAddress:int) -> list:
 x = Script
 y = 0
 ClassName = GetClassName(Script)
 if ClassName == 'LocalScript':
  y = x + 0x140
 if ClassName == 'ModuleScript':
  y = x + 0x124
 if y == 0:
  return None
 ProtectedStringRegion = Hacker.DRP(y)
 ProtectedStringRegionData = Hacker.Pymem.read_bytes(ProtectedStringRegion,20,true)
 ScriptByteCodeAddress = ProtectedStringRegion + 0x10
 LengthA = ScriptByteCodeAddress + 0x10
 LengthB = LengthA + 4
 OriginalByteCode = GetByteCode(ScriptByteCodeAddress)
 NewMemoryRegion = GetStoredOScripts(ProtectedStringRegion)
 if NewMemoryRegion:
  print("Memory exists, overwritting...")
  Hacker.Pymem.write_int(y,NewMemoryRegion)
  return [NewMemoryRegion,ProtectedStringRegion,OriginalByteCode]
 else:
  print("Making New Memory in OverwriteByteCode function")
  NewMemoryRegion = Hacker.Pymem.allocate(64)
  StoredOScripts.update({ByteCodeAddress:NewMemoryRegion})
  Hacker.Pymem.write_bytes(NewMemoryRegion,ProtectedStringRegionData,20)
  Hacker.Pymem.write_int(NewMemoryRegion + 0x10,Hacker.Pymem.read_int(ByteCodeAddress))
  Hacker.Pymem.write_int(NewMemoryRegion + 0x20,Hacker.Pymem.read_int(ByteCodeAddress + 0x10))
  Hacker.Pymem.write_int(NewMemoryRegion + 0x24,Hacker.Pymem.read_int(ByteCodeAddress + 0x14))
  Hacker.Pymem.write_int(y,NewMemoryRegion)
 return [NewMemoryRegion,ProtectedStringRegion,OriginalByteCode]

def GetScriptByteCode(Script:int) -> str:
 ClassName = GetClassName(Script)
 if ClassName == 'LocalScript':
  return GetByteCode(GetByteCodeAddress(Script))
 if ClassName == 'ModuleScript':
  return GetByteCode(GetByteCodeAddress(Script))
 print("Invalid support in GetScriptByteCode for Class: " + str(ClassName))





def GetIdentity(LuaState:int) -> int:
 SharedMemory = Hacker.DRP(LuaState + RobloxExtraSpace_Offset)
 Identity = SharedMemory + Identity_Offset
 return Hacker.Pymem.read_int(Identity)

def SetIdentity(LuaState:int,Level:int):
 SharedMemory = Hacker.DRP(LuaState + RobloxExtraSpace_Offset)
 Identity = SharedMemory + Identity_Offset
 Hacker.Pymem.write_int(Identity,Level)


def CompileToRobloxByteCode(RobloxLuaStringSource:str) -> str:
 Source = RobloxLuaStringSource
 CompilerDIR = os.getenv('userprofile')+'\\Desktop\\rbxcompile.exe'
 InputFileDIR = os.getenv('userprofile')+'\\Desktop\\input.luau'
 OutputFileDIR = os.getenv('userprofile')+'\\Desktop\\output.encrbxluauc'
 Compiler = os.path.exists(CompilerDIR)
 if not Compiler:
  if DownloadCompiler:
   print("Downloading Epix's Compiler...")
   x = requests.get('https://github.com/EpixScripts/rbxcompile/releases/download/v1.0.1/rbxcompile.exe')
   y = open(CompilerDIR, 'wb')
   y.write(x.content)
   y.close()
   print("Done downloading the Compiler! Default locatoin is in Desktop!")
  else:
   print("You decided not to download the compiler while not having a compiler, you can't compile Roblox ByteCode, so rloadstring won't work.")
   return None
 InputFile = open(InputFileDIR, 'w')
 InputFile.write(Source)
 InputFile.close()
 os.system('cd ' + os.getenv('userprofile')+'\\Desktop & ' + CompilerDIR)
 OutputFile = open(OutputFileDIR,'rb')
 RawCompiledByteCode = OutputFile.read()
 HexCompiledByteCode = RawCompiledByteCode.hex()
 OutputFile.close()
 return HexCompiledByteCode



def GetState() -> int:
 if not GetDataModelFromNetPeerSend():
  return None
 NewMemory = Hacker.Pymem.allocate(100)
 Argument = NewMemory + 0x40
 Mov_ECX_ScriptContext = 'B9' + Hacker.hex2le(GetService("ScriptContext"))
 Push_Arg1 = '68' + Hacker.hex2le(Argument)
 Push_Arg2 = '68' + Hacker.hex2le(Argument)
 Call_GetState_Function = 'E8' + Hacker.hex2le(Hacker.calcjmpop(Hacker.getAddressFromName(GetStateFunctionAddress),NewMemory + 15))
 Mov_Base_Eax = 'A3' + Hacker.hex2le(NewMemory + 0x30)
 Ret = 'C3'
 FullHexString = Mov_ECX_ScriptContext + Push_Arg1 + Push_Arg2 + Call_GetState_Function + Mov_Base_Eax + Ret
 Hacker.Pymem.write_bytes(NewMemory,bytes.fromhex(FullHexString),Hacker.gethexc(FullHexString))
 Hacker.Pymem.start_thread(NewMemory)
 ReturnValue = Hacker.Pymem.read_int(NewMemory + 0x30)
 Hacker.Pymem.free(NewMemory)
 return ReturnValue

def LuaVMLoad(LuaState:int,ByteCodeAddress:int,ChunkName:str,ENV_Optional='00') -> bool:
 NewMemory = Hacker.Pymem.allocate(100)
 ChunkNameAddress = Hacker.Pymem.allocate(len(ChunkName) + 20)
 Hacker.Pymem.write_string(ChunkNameAddress,ChunkName)
 Mov_ECX_LuaState = 'B9' + Hacker.hex2le(LuaState)
 Mov_EDX_ByteCodeAddress = 'BA' + Hacker.hex2le(ByteCodeAddress)
 Push_ENV_Optional = '6A' + ENV_Optional
 Push_ChunkNameAddress = '68' + Hacker.hex2le(ChunkNameAddress)
 Call_LuaVMLoad = 'E8' + Hacker.hex2le(Hacker.calcjmpop(Hacker.getAddressFromName(LuaVMLoadFunctionAddress),NewMemory + 0x11))
 Add_ESP_8 = '83 C4 08'
 Ret = 'C3'
 FullHexString = Mov_ECX_LuaState + Mov_EDX_ByteCodeAddress + Push_ENV_Optional + Push_ChunkNameAddress + Call_LuaVMLoad + Add_ESP_8 + Ret
 Hacker.Pymem.write_bytes(NewMemory,bytes.fromhex(FullHexString),Hacker.gethexc(FullHexString))
 Hacker.Pymem.start_thread(NewMemory)
 Hacker.Pymem.free(NewMemory)
 return True

def Task_Defer(LuaState:int) -> bool:
 NewMemory = Hacker.Pymem.allocate(100)
 Push_LuaState = '68' + Hacker.hex2le(LuaState)
 Call_Task_Defer = 'E8' + Hacker.hex2le(Hacker.calcjmpop(Hacker.getAddressFromName(Task_Defer_FunctionAddress),NewMemory + 0x5))
 Add_ESP_4 = '83 C4 04'
 Ret = 'C3'
 FullHexString = Push_LuaState + Call_Task_Defer + Add_ESP_4 + Ret
 Hacker.Pymem.write_bytes(NewMemory,bytes.fromhex(FullHexString),Hacker.gethexc(FullHexString))
 Hacker.Pymem.start_thread(NewMemory)
 Hacker.Pymem.free(NewMemory)
 return True


def ByteCodeExecution(ScriptSource:str,Identity:int=6):
 if not Hacker.isProgramGameActive():
  return None
 if not GetDataModelFromNetPeerSend():
  return None
 LuaState = GetState()
 Original = Hacker.Pymem.read_int(LuaState + Lua_Top)
 RobloxSourceToExecute = 'spawn(function() ' + ScriptSource + ' end)'
 SetIdentity(LuaState,Identity)
 HexStringDataOfByteCode = CompileToRobloxByteCode(RobloxSourceToExecute)
 ByteCodeAddress = MakeByteCodeAddress(HexStringDataOfByteCode)
 LuaVMLoad(LuaState,ByteCodeAddress,'=PyExe')
 Task_Defer(LuaState)
 Hacker.Pymem.write_int(LuaState + Lua_Top,Original)

def ByteCodeExecutionRunByteCode(ByteCodeAddress:int,Identity=6):
 if not Hacker.isProgramGameActive():
  return None
 if not GetDataModelFromNetPeerSend():
  return None
 LuaState = GetState()
 Original = Hacker.Pymem.read_int(LuaState + Lua_Top)
 SetIdentity(LuaState,Identity)
 LuaVMLoad(LuaState,ByteCodeAddress,'=PyExe')
 Task_Defer(LuaState)
 Hacker.Pymem.write_int(LuaState + Lua_Top,Original)

def rloadstring(RobloxLuaStringSource:str):
 ByteCodeExecution(RobloxLuaStringSource)






window = tk.Tk()

window.title('Python Script Executor v2')
window.resizable(width=False, height=False)
window.attributes('-topmost',True)

frm_1 = tk.Frame(master=window)
frm_1.pack()
frm_2 = tk.Frame(master=window)
frm_2.pack()
frm_3 = tk.Frame(master=window)
frm_3.pack()

sct_1 = scrolledtext.ScrolledText(frm_2, width = 80, height = 20,wrap=tk.WORD)
sct_1.pack()

def ClearFunctionButton():
 sct_1.delete('1.0',tk.END)

def ExecuteFunctionButton():
 if Hacker.isProgramGameActive():
  rloadstring(sct_1.get('1.0',tk.END))
 else:
  print("Game is no longer active")

btn_Clear = tk.Button(frm_3, text="Clear", fg='black', bg='red', font=('Arial',11), width=16,height=8, relief=tk.RAISED,borderwidth=3,command=ClearFunctionButton)
btn_Clear.pack(side=tk.LEFT,padx=64)

btn_Execute = tk.Button(frm_3, text="Execute", fg='white', bg='blue', font=('Arial',11), width=16,height=8, relief=tk.RAISED,borderwidth=3,command=ExecuteFunctionButton)
btn_Execute.pack(side=tk.RIGHT,padx=64)


window.mainloop()

