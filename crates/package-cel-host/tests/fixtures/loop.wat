(module
  (memory (export "memory") 1)
  (func (export "guest_abi_version") (result i32) i32.const 2)
  (func (export "guest_allocate") (param i32) (result i32) i32.const 16)
  (func (export "guest_evaluate") (param i32 i32) (result i64)
    (loop $spin (br $spin)) unreachable))
