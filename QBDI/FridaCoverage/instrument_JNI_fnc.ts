import { handle_new_bb, generate_drcov_file, coverage_data } from "./drcov_utils.js";

import {
    VM,
    SyncDirection,
    InstPosition,
    VMAction,
    VMEvent,
    Options
  } from "./frida-qbdi.js";

// For whatever forsaken reason THIS ONLY WORKS RELIABLE WHEN THE APP IS IN BACKGROUND
function qbdi_test_2(){
  const java_vm = Java.vm.getEnv()
  var jstring_str = java_vm.newStringUtf("supersecret")
  var vm = new VM(); // create a QBDI VM
  var state = vm.getGPRState();
  var stack = vm.allocateVirtualStack(state, 0x80000); // allocate a virtual stack
  const fnc_ptr = DebugSymbol.getFunctionByName("_Z9checkPassP7_JNIEnvP8_jstring")
  vm.addInstrumentedModuleFromAddr(fnc_ptr);
  var InstructionCallback = vm.newInstCallback(function (vm, gpr, fpr, data) {
    var inst = vm.getInstAnalysis();
    //gpr.dump(); // display the context
    console.log("0x" + inst.address.toString(16) + " " + inst.disassembly); // display the instruction
    return VMAction.CONTINUE;
  });
  var iid = vm.addCodeCB(InstPosition.PREINST, InstructionCallback, null);
  var vcbk = vm.newVMCallback(function (vm, evt, gpr, fpr, data) {
    const module = Process.getModuleByAddress(ptr(evt.basicBlockStart));
    const base_addr = ptr(evt.basicBlockStart).sub(module.base); // address must be relative to the module's start
    const size = evt.basicBlockEnd - evt.basicBlockStart;
    handle_new_bb({start: Number(base_addr), size: size, mod_id: 0x0}, module)
    return VMAction.CONTINUE;
  });
  var vid = vm.addVMEventCB(VMEvent.BASIC_BLOCK_NEW, vcbk, null);
  var result = vm.call(fnc_ptr, [java_vm.handle, jstring_str])
  var msg = (result.toInt32() == 0x1) ? "Correct password!" : "Wrong password"
  console.log("[+] " + msg)

  generate_drcov_file(coverage_data, "/data/data/infosecadventures.allsafe")
}

(global as any).qbdi_test_2 = qbdi_test_2