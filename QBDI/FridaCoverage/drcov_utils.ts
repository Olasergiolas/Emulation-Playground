import { normalize, join } from "path";

export {handle_new_bb, generate_drcov_file, coverage_data}

interface drcov_module {
    id: number,
    base: number,
    end: number,
    path: string
  }
  
  interface drcov_bb {
    start: number,
    size: number,
    mod_id: number
  }
  
  let coverage_data: Map<number, [drcov_module, [drcov_bb]]> = new Map()
  let mod_i = 0
  let number_of_bbs = 0
  function handle_new_bb(bb: drcov_bb, module: Module){
    var mod_already_saved = -1
  
    for (let t of coverage_data) {
      if (t[1][0].path == module.path){
        mod_already_saved = t[1][0].id
        break
      }
    }
  
    if (mod_already_saved !== -1){  // Already saved
      var mod_entry = coverage_data.get(mod_already_saved)
      if (!mod_entry)
        return
  
      mod_entry[1].push(bb)
      coverage_data.set(mod_already_saved, mod_entry)
      number_of_bbs += 1
    }
  
    else{
      bb.mod_id = mod_i
      coverage_data.set(mod_i, [{id: mod_i, base: Number(module.base), end: Number(module.base.add(module.size)), path: module.path}, [bb]])
      mod_i += 1
      number_of_bbs += 1
    }
  }
  
  function generate_drcov_file(coverage_data: Map<number, [drcov_module, [drcov_bb]]>, dir_path: string): boolean{
    var final_path = join(normalize(dir_path), "drcov.bin")
    var f = new File(final_path, "wb")
  
    if (!f)
      return false
  
    f.write("DRCOV VERSION: 2\nDRCOV FLAVOR: drcov\n")
    f.write(`Module Table: version 2, count ${coverage_data.size}\n`)
    f.write("Columns: id, base, end, entry, checksum, timestamp, path\n")
    for (let mod of coverage_data)
      f.write(`${mod[1][0].id}, ${"0x" + mod[1][0].base.toString(16)}, ${"0x" + mod[1][0].end.toString(16)}, ${0x0}, ${0x0}, ${0x0}, ${mod[1][0].path}\n`)
  
    f.write(`BB Table: ${number_of_bbs} bbs\n`)

    for (let mod of coverage_data){
      for (let bb of mod[1][1]){
        console.log(`Saving bb with start: ${bb.start}, size: ${bb.size} and mod_id: ${bb.mod_id}`)
        var ab = new Uint32Array([bb.start]).buffer
        f.write(ab as ArrayBuffer)
        ab = new Uint16Array([bb.size]).buffer
        f.write(ab as ArrayBuffer)
        ab = new Uint16Array([bb.mod_id]).buffer
        f.write(ab as ArrayBuffer)
      }
    }
  
    f.flush()
    f.close()
  
    return true
  }