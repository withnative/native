(module
  (memory (export "memory") 17)
  (global $sp (mut i32) (i32.const 1048576))
  (func (export "guest_abi_version") (result i32) i32.const 2)
  (func (export "guest_allocate") (param i32) (result i32) i32.const 16)
  (func (export "guest_evaluate") (param i32 i32) (result i64)
    ;; Constant call depth, downward 1MiB linear stack; underflow traps in memory.
    (loop $push
      (global.set $sp (i32.sub (global.get $sp) (i32.const 16384)))
      (i32.store (global.get $sp) (i32.const 1))
      (br $push)) unreachable))
