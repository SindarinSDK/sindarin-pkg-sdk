use std::ffi::c_void;
#[repr(C)]
struct Random { rc: i32, is_seeded: i32, state: i64 }
#[repr(C)]
#[derive(Clone, Copy)]
struct ArrayType { leaf_kind: u32, rank: u32 }
extern "C" {
    fn sn_random_create_with_seed(seed: i64) -> *mut Random;
    fn sn_random_int(value: *mut Random, min: i64, max: i64) -> i64;
    fn sn_random_int_many(value: *mut Random, min: i64, max: i64, count: i64) -> *mut c_void;
    fn sn_random_free(value: *mut Random);
    fn sn_sdk_random_retain(value: *mut Random) -> *mut Random;
    fn sn_sdk_random_release(value: *mut Random);
    fn sn_sdk_random_refs(value: *mut Random) -> i32;
    fn sn_abi_v1_native_array_adopt(array: *mut c_void, shape: ArrayType, out: *mut *mut c_void) -> u32;
    fn sn_abi_v1_native_array_data(value: *mut c_void, shape: ArrayType, out: *mut *mut c_void) -> u32;
    fn sn_array_get(value: *mut c_void, index: i64) -> *mut c_void;
    fn sn_abi_v1_release(value: *mut c_void);
}
fn main() {
    unsafe {
        assert_eq!(std::mem::size_of::<Random>(), 16);
        let rng = sn_random_create_with_seed(42);
        let same = sn_random_create_with_seed(42);
        assert!(!rng.is_null() && (*rng).state != 0 && (*rng).is_seeded == 1);
        assert_eq!(sn_sdk_random_refs(rng), 1);
        let alias = sn_sdk_random_retain(rng);
        assert_eq!(alias, rng);
        assert_eq!(sn_sdk_random_refs(rng), 2);
        let numbers = sn_random_int_many(alias, 10, 20, 4);
        let shape = ArrayType { leaf_kind: 1, rank: 1 };
        let mut wire = std::ptr::null_mut();
        assert_eq!(sn_abi_v1_native_array_adopt(numbers, shape, &mut wire), 0);
        sn_sdk_random_release(alias);
        sn_sdk_random_release(rng);
        let mut header = std::ptr::null_mut();
        assert_eq!(sn_abi_v1_native_array_data(wire, shape, &mut header), 0);
        assert_eq!(header, numbers);
        for i in 0..4 {
            assert_eq!(*sn_array_get(header, i).cast::<i64>(), sn_random_int(same, 10, 20));
        }
        sn_abi_v1_release(wire);
        sn_random_free(same); sn_random_free(same);
        assert_eq!((*same).state, 0);
        sn_sdk_random_release(same);
    }
    println!("SDK canonical Random Rust: pass");
}
