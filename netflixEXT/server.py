## this file was developed by darian (not.darian) and the nce development team
import pymem
import re
import time
import ctypes

## creds meow

print(r'''                                                     
                  ___                 __                 
    __ _  __ _   / / |__  _   _  ___ / _|_ __ ___  _ __  
   / _` |/ _` | / /| '_ \| | | |/ _ \ |_| '__/ _ \| '_ \ 
  | (_| | (_| |/ / | |_) | |_| |  __/  _| | | (_) | | | |
 (_)__, |\__, /_/  |_.__/ \__, |\___|_| |_|  \___/|_| |_|
   |___/ |___/            |___/                                                                           
''')

## we ontop
class Netflix:
    def __init__(self, ProgramName=None):
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

    def h2d(self, hz: str, bit: int = 16) -> int:
        if type(hz) == int:
            return hz
        return int(hz, bit)

    def d2h(self, dc: int, UseAuto=None) -> str:
        if type(dc) == str:
            return dc
        if UseAuto:
            if UseAuto == 32:
                dc = hex(dc & (2**32 - 1)).replace("0x", "")
            else:
                dc = hex(dc & (2**64 - 1)).replace("0x", "")
        else:
            if abs(dc) > 4294967295:
                dc = hex(dc & (2**64 - 1)).replace("0x", "")
            else:
                dc = hex(dc & (2**32 - 1)).replace("0x", "")
        if len(dc) > 8:
            while len(dc) < 16:
                dc = "0" + dc
        if len(dc) < 8:
            while len(dc) < 8:
                dc = "0" + dc
        return dc

    def PLAT(self, aob: str):
        if type(aob) == bytes:
            return aob
        trueB = bytearray(b"")
        aob = aob.replace(" ", "")
        PLATlist = []
        for i in range(0, len(aob), 2):
            PLATlist.append(aob[i : i + 2])
        for i in PLATlist:
            if "?" in i:
                trueB.extend(b".")
            if "?" not in i:
                trueB.extend(re.escape(bytes.fromhex(i)))
        return bytes(trueB)

    def AOBSCANALL(self, AOB_HexArray, xreturn_multiple=False):
        return pymem.pattern.pattern_scan_all(
            self.Pymem.process_handle,
            self.PLAT(AOB_HexArray),
            return_multiple=xreturn_multiple,
        )

    def gethexc(self, hex: str):
        hex = hex.replace(" ", "")
        hxlist = []
        for i in range(0, len(hex), 2):
            hxlist.append(hex[i : i + 2])
        return len(hxlist)

    def hex2le(self, hex: str):
        lehex = hex.replace(" ", "")
        lelist = []
        if len(lehex) > 8:
            while len(lehex) < 16:
                lehex = "0" + lehex
            for i in range(0, len(lehex), 2):
                lelist.append(lehex[i : i + 2])
            lelist.reverse()
            return "".join(lelist)
        if len(lehex) < 9:
            while len(lehex) < 8:
                lehex = "0" + lehex
            for i in range(0, len(lehex), 2):
                lelist.append(lehex[i : i + 2])
            lelist.reverse()
            return "".join(lelist)

    def calcjmpop(self, des, cur):
        jmpopc = (self.h2d(des) - self.h2d(cur)) - 5
        jmpopc = hex(jmpopc & (2**32 - 1)).replace("0x", "")
        if len(jmpopc) % 2 != 0:
            jmpopc = "0" + str(jmpopc)
        return jmpopc

    def isProgramGameActive(self):
        try:
            self.Pymem.read_char(self.Pymem.base_address)
            return True
        except:
            return False

    def DRP(self, Address: int, is64Bit: bool = None) -> int:
        Address = Address
        if type(Address) == str:
            Address = self.h2d(Address)
        if is64Bit:
            return int.from_bytes(self.Pymem.read_bytes(Address, 8), "little")
        if self.is64bit:
            return int.from_bytes(self.Pymem.read_bytes(Address, 8), "little")
        return int.from_bytes(self.Pymem.read_bytes(Address, 4), "little")

    def isValidPointer(self, Address: int, is64Bit: bool = None) -> bool:
        try:
            if type(Address) == str:
                Address = self.h2d(Address)
            self.Pymem.read_bytes(self.DRP(Address, is64Bit), 1)
            return True
        except:
            return False

    def GetModules(self) -> list:
        return list(self.Pymem.list_modules())

    def getAddressFromName(self, Address: str) -> int:
        if type(Address) == int:
            return Address
        AddressBase = 0
        AddressOffset = 0
        for i in self.GetModules():
            if i.name in Address:
                AddressBase = i.lpBaseOfDll
                AddressOffset = self.h2d(Address.replace(i.name + "+", ""))
                AddressNamed = AddressBase + AddressOffset
                return AddressNamed
        print("Unable to find Address: " + Address)
        return Address

    def getNameFromAddress(self, Address: int) -> str:
        memoryInfo = pymem.memory.virtual_query(self.Pymem.process_handle, Address)
        BaseAddress = memoryInfo.BaseAddress
        NameOfDLL = ""
        AddressOffset = 0
        for i in self.GetModules():
            if i.lpBaseOfDll == BaseAddress:
                NameOfDLL = i.name
                AddressOffset = Address - BaseAddress
                break
        if NameOfDLL == "":
            return Address
        NameOfAddress = NameOfDLL + "+" + self.d2h(AddressOffset)
        return NameOfAddress

    def getRawProcesses(self):
        toreturn = []
        for i in pymem.process.list_processes():
            toreturn.append(
                [
                    i.cntThreads,
                    i.cntUsage,
                    i.dwFlags,
                    i.dwSize,
                    i.pcPriClassBase,
                    i.szExeFile,
                    i.th32DefaultHeapID,
                    i.th32ModuleID,
                    i.th32ParentProcessID,
                    i.th32ProcessID,
                ]
            )
        return toreturn

    def SimpleGetProcesses(self):
        toreturn = []
        for i in self.getRawProcesses():
            toreturn.append({"Name": i[5].decode(), "Threads": i[0], "ProcessId": i[9]})
        return toreturn

    def YieldForProgram(self, programName, AutoOpen: bool = False, Limit=15):
        Count = 0
        while True:
            if Count > Limit:
                print("Yielded too long, failed!")
                return False
            ProcessesList = self.SimpleGetProcesses()
            for i in ProcessesList:
                if i["Name"] == programName:
                    print(
                        "Found "
                        + programName
                        + " with Process ID: "
                        + str(i["ProcessId"])
                    )
                    if AutoOpen:
                        self.Pymem.open_process_from_id(i["ProcessId"])
                        self.ProgramName = programName
                        self.Handle = self.Pymem.process_handle
                        self.is64bit = not pymem.process.is_64_bit(self.Handle)
                        self.ProcessID = self.Pymem.process_id
                        self.PID = self.ProcessID
                        print("Successfully attached to Process.")
                    return True
            time.sleep(1)
            Count += 1

    def ReadPointer(
        self, BaseAddress: int, Offsets_L2R: list, is64Bit: bool = None
    ) -> int:
        x = self.DRP(BaseAddress, is64Bit)
        y = Offsets_L2R
        z = x
        if y == None or len(y) == 0:
            return z
        count = 0
        for i in y:
            try:
                print(self.d2h(x + i))
                print(self.d2h(i))
                z = self.DRP(z + i, is64Bit)
                count += 1
                print(self.d2h(z))
            except:
                print("Failed to read Offset at Index: " + str(count))
                return z
        return z

    def GetMemoryInfo(self, Address: int, Handle: int = None):
        if Handle:
            return pymem.memory.virtual_query(Handle, Address)
        else:
            return pymem.memory.virtual_query(self.Handle, Address)

    def MemoryInfoToDictionary(self, MemoryInfo):
        return {
            "BaseAddress": MemoryInfo.BaseAddress,
            "AllocationBase": MemoryInfo.AllocationBase,
            "AllocationProtect": MemoryInfo.AllocationProtect,
            "RegionSize": MemoryInfo.RegionSize,
            "State": MemoryInfo.State,
            "Protect": MemoryInfo.Protect,
            "Type": MemoryInfo.Type,
        }

    def SetProtection(
        self,
        Address: int,
        ProtectionType=0x40,
        Size: int = 4,
        OldProtect=ctypes.c_ulong(0),
    ):
        pymem.ressources.kernel32.VirtualProtectEx(
            self.Pymem.process_handle,
            Address,
            Size,
            ProtectionType,
            ctypes.byref(OldProtect),
        )
        return OldProtect

    def ChangeProtection(
        self,
        Address: int,
        ProtectionType=0x40,
        Size: int = 4,
        OldProtect=ctypes.c_ulong(0),
    ):
        return self.SetProtection(Address, ProtectionType, Size, OldProtect)

    def GetProtection(self, Address: int):
        return self.GetMemoryInfo(Address).Protect

    def KnowProtection(self, Protection):
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
        if Protection in ["PAGE_EXECUTE", "execute", "e"]:
            return 0x10
        if Protection in [
            "PAGE_EXECUTE_READ",
            "execute read",
            "read execute",
            "execute_read",
            "read_execute",
            "er",
            "re",
        ]:
            return 0x20
        if Protection in [
            "PAGE_EXECUTE_READWRITE",
            "execute read write",
            "execute write read",
            "write execute read",
            "write read execute",
            "read write execute",
            "read execute write",
            "erw",
            "ewr",
            "wre",
            "wer",
            "rew",
            "rwe",
        ]:
            return 0x40
        if Protection in [
            "PAGE_EXECUTE_WRITECOPY",
            "execute copy write",
            "execute write copy",
            "write execute copy",
            "write copy execute",
            "copy write execute",
            "copy execute write",
            "ecw",
            "ewc",
            "wce",
            "wec",
            "cew",
            "cwe",
        ]:
            return 0x80
        if Protection in ["PAGE_NOACCESS", "noaccess", "na", "n"]:
            return 0x01
        if Protection in ["PAGE_READONLY", "readonly", "ro", "r"]:
            return 0x02
        if Protection in ["PAGE_READWRITE", "read write", "write read", "wr", "rw"]:
            return 0x04
        if Protection in ["PAGE_WRITECOPY", "write copy", "copy write", "wc", "cw"]:
            return 0x08
        if Protection in ["PAGE_GUARD", "pg", "guard", "g"]:
            return 0x100
        if Protection in ["PAGE_NOCACHE", "nc", "nocache"]:
            return 0x200
        if Protection in ["PAGE_WRITECOMBINE", "write combine", "combine write"]:
            return 0x400
        return Protection

    def Suspend(self, pid: int = None):
        kernel32 = ctypes.WinDLL("kernel32.dll")
        if pid:
            kernel32.DebugActiveProcess(pid)
        if self.PID:
            kernel32.DebugActiveProcess(self.PID)

    def Resume(self, pid: int = None):
        kernel32 = ctypes.WinDLL("kernel32.dll")
        if pid:
            kernel32.DebugActiveProcessStop(pid)
        if self.PID:
            kernel32.DebugActiveProcessStop(self.PID)

Netflix = Netflix()

print("Waiting for roblox")
while True:
    if Netflix.YieldForProgram("RobloxPlayerBeta.exe", True, 60):
        break
    if Netflix.YieldForProgram("Windows10Universal.exe", True, 60):
        break
print("Roblox Opened.")

def ReadRobloxString(ExpectedAddress: int) -> str:
    StringCount = Netflix.Pymem.read_int(ExpectedAddress + 0x10)
    if StringCount > 15:
        return Netflix.Pymem.read_string(Netflix.DRP(ExpectedAddress), StringCount)
    return Netflix.Pymem.read_string(ExpectedAddress, StringCount)

def GetClassName(Instance: int) -> str:
    ExpectedAddress = Netflix.DRP(Netflix.DRP(Instance + 0x18) + 8)
    return ReadRobloxString(ExpectedAddress)

def setParent(Instance, Parent):
    Netflix.Pymem.write_longlong(Instance + parentOffset, Parent)
    newChildren = Netflix.Pymem.allocate(0x400)
    Netflix.Pymem.write_longlong(newChildren + 0, newChildren + 0x40)
    ptr = Netflix.Pymem.read_longlong(Parent + childrenOffset)
    childrenStart = Netflix.Pymem.read_longlong(ptr)
    childrenEnd = Netflix.Pymem.read_longlong(ptr + 8)
    b = Netflix.Pymem.read_bytes(childrenStart, childrenStart - childrenEnd)
    Netflix.Pymem.write_bytes(newChildren + 0x40, b, len(b))
    e = newChildren + 0x40 + (childrenEnd - childrenStart)
    Netflix.Pymem.write_longlong(e, Instance)
    Netflix.Pymem.write_longlong(e + 8, Netflix.Pymem.read_longlong(Instance + 0x10))
    e = e + 0x10
    Netflix.Pymem.write_longlong(newChildren + 0x8, e)
    Netflix.Pymem.write_longlong(newChildren + 0x10, e)

## uses everything to inject
def inject():
    players = 0
    nameOffset = 0
    valid = False
    results = Netflix.AOBSCANALL(
        "506C6179657273??????????????????07000000000000000F", True
    )
    if not results:
        input("FAILED BADLY! PLEASE REPORT THIS TO DISCORD")
        exit()
    for rn in results:
        result = rn
        if not result:
            input("Failed!")
            exit()
        bres = Netflix.d2h(result)
        aobs = ""
        for i in range(1, 16 + 1):
            aobs = aobs + bres[i - 1 : i]
        aobs = Netflix.hex2le(aobs)
        first = False
        res = Netflix.AOBSCANALL(aobs, True)
        if res:
            valid = False
            for i in res:
                try:
                    result = i
                    for j in range(1, 10 + 1):
                        address = result - (8 * j)
                        if not Netflix.isValidPointer(address):
                            continue
                        ptr = Netflix.Pymem.read_longlong(address)
                        if Netflix.isValidPointer(ptr):
                            address = ptr + 8
                            if not Netflix.isValidPointer(address):
                                continue
                            ptr = Netflix.Pymem.read_longlong(address)
                            if (
                                Netflix.Pymem.read_string(ptr) == "Players"
                            ): 
                                if not first:
                                    first = True
                                    players = (result - (8 * j)) - 0x18
                                    nameOffset = result - players
                                else:
                                    players = (result - (8 * j)) - 0x18
                                    nameOffset = result - players
                                    break
                    if valid:
                        break
                except:
                    pass
            if valid:
                break
        print("Injection: Detected Player Service")
    if players == 0:
        print("Failed to get Players service!")
        return None
    parentOffset = 0
    for i in range(0x10, 0x120 + 8, 8):
        address = players + i
        if not Netflix.isValidPointer(address):
            continue
        ptr = Netflix.Pymem.read_longlong(address)
        if ptr != 0 and ptr % 4 == 0:
            address = ptr + 8
            if not Netflix.isValidPointer(address):
                continue
            if Netflix.Pymem.read_longlong(address) == ptr:
                parentOffset = i
                break
    if parentOffset == 0:
        print("Failed to get Parent Offset!")
        return None
    dataModel = Netflix.Pymem.read_longlong(players + parentOffset)
    childrenOffset = 0
    for i in range(0x10, 0x200 + 8, 8):
        ptr = Netflix.Pymem.read_longlong(dataModel + i)
        if ptr:
            try:
                childrenStart = Netflix.Pymem.read_longlong(ptr)
                childrenEnd = Netflix.Pymem.read_longlong(ptr + 8)
                if childrenStart and childrenEnd:
                    if (
                        childrenEnd > childrenStart
                        and childrenEnd - childrenStart > 1
                        and childrenEnd - childrenStart < 0x1000
                    ):
                        childrenOffset = i
                        break
            except:
                pass
    print("Injection: Found children (not humans lmao - darian)")

    def GetNameAddress(Instance: int) -> int:
        ExpectedAddress = Netflix.DRP(Instance + nameOffset, True)
        return ExpectedAddress

    def GetName(Instance: int) -> str:
        ExpectedAddress = GetNameAddress(Instance)
        return ReadRobloxString(ExpectedAddress)

    def GetChildren(Instance: int) -> str:
        ChildrenInstance = []
        InstanceAddress = Instance
        if not InstanceAddress:
            return False
        ChildrenStart = Netflix.DRP(InstanceAddress + childrenOffset, True)
        if ChildrenStart == 0:
            return []
        ChildrenEnd = Netflix.DRP(ChildrenStart + 8, True)
        OffsetAddressPerChild = 0x10
        CurrentChildAddress = Netflix.DRP(ChildrenStart, True)
        for i in range(0, 9000):
            if i == 8999:
                print("WARNING: Too many children, could be invalid")
            if CurrentChildAddress == ChildrenEnd:
                break
            ChildrenInstance.append(Netflix.Pymem.read_longlong(CurrentChildAddress))
            CurrentChildAddress += OffsetAddressPerChild
        return ChildrenInstance

    def GetParent(Instance: int) -> int:
        return Netflix.DRP(Instance + parentOffset, True)

    def FindFirstChild(Instance: int, ChildName: str) -> int:
        ChildrenOfInstance = GetChildren(Instance)
        for i in ChildrenOfInstance:
            if GetName(i) == ChildName:
                return i

    def FindFirstChildOfClass(Instance: int, ClassName: str) -> int:
        ChildrenOfInstance = GetChildren(Instance)
        for i in ChildrenOfInstance:
            if GetClassName(i) == ClassName:
                return i

    class toInstance:
        def __init__(self, address: int = 0):
            self.Address = address
            self.Self = address
            self.Name = GetName(address)
            self.ClassName = GetClassName(address)
            self.Parent = GetParent(address)

        def getChildren(self):
            return GetChildren(self.Address)

        def findFirstChild(self, ChildName):
            return FindFirstChild(self.Address, ChildName)

        def findFirstClass(self, ChildClass):
            return FindFirstChildOfClass(self.Address, ChildClass)

        def setParent(self, Parent):
            SetParent(self.Address, Parent)

        def GetChildren(self):
            return GetChildren(self.Address)

        def FindFirstChild(self, ChildName):
            return FindFirstChild(self.Address, ChildName)

        def FindFirstClass(self, ChildClass):
            return FindFirstChildOfClass(self.Address, ChildClass)

        def SetParent(self, Parent):
            SetParent(self.Address, Parent)

    players = toInstance(players)
    game = toInstance(dataModel)
    localPlayerOffset = 0
    for i in range(0x10, 0x600 + 4, 4):
        ptr = Netflix.Pymem.read_longlong(players.Self + i)
        if not Netflix.isValidPointer(ptr):
            continue
        if Netflix.Pymem.read_longlong(ptr + parentOffset) == players.Self:
            localPlayerOffset = i
            break
    localPlayer = toInstance(Netflix.DRP(players.Self + localPlayerOffset))
    print("Injection: Found localplayer")
    localBackpack = toInstance(localPlayer.FindFirstClass("Backpack"))
    print("Injection: Found Backpack")
    tools = localBackpack.GetChildren()
    if len(tools) == 0:
        input("ERROR: NO TOOLS FOUND\nPlease retry this process with another game")
        exit()
    tool = toInstance(tools[0])
    print("Injection: Injecting in: ", tool.Name)
    targetScript = toInstance(tool.findFirstClass("LocalScript"))
    print("Injection: Found tool script")
    injectScript = None
    results = Netflix.AOBSCANALL("496E6A656374????????????????????06", True)
    if results == []:
        input("ERROR: No script localscript found in tool")
        exit()
    for rn in results:
        result = rn
        bres = Netflix.d2h(result)
        aobs = ""
        for i in range(1, 16 + 1):
            aobs = aobs + bres[i - 1 : i]
        aobs = Netflix.hex2le(aobs)
        first = False
        res = Netflix.AOBSCANALL(aobs, True)
        if res:
            valid = False
            for i in res:
                result = i
                if (
                    Netflix.Pymem.read_longlong(result - nameOffset + 8)
                    == result - nameOffset
                ):
                    injectScript = result - nameOffset
                    valid = True
                    break
        if valid:
            break
    injectScript = toInstance(injectScript)
    print("Successfully injected :", Netflix.d2h(injectScript.Self))
    b = Netflix.Pymem.read_bytes(injectScript.Self + 0x100, 0x150)
    Netflix.Pymem.write_bytes(targetScript.Self + 0x100, b, len(b))
    return True


## print and alerts
print("Join the following place and teleport to your desired game. Make sure it has tools")
print("roblox.com/games/15167092402")

input(
    "When you have teleported, press enter"
)

print("Injecting... If roblox freezes during this state, do not panic. Just wait.")

if inject():
    print("Injected. Please equip the tool multiple times until the UI shows.")
else:
    print("Error. Please redo this process and report back to the discord: discord.gg/byefron")