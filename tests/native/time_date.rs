use std::ffi::CStr;
#[repr(C)]
struct Time {
    rc: i32,
    milliseconds: i64,
}
#[repr(C)]
struct Date {
    rc: i32,
    days: i32,
}
extern "C" {
    fn sn_time_from_millis(value: i64) -> *mut Time;
    fn sn_time_to_iso(value: *mut Time) -> *mut std::ffi::c_char;
    fn sn_sdk_time_retain(value: *mut Time) -> *mut Time;
    fn sn_sdk_time_release(value: *mut Time);
    fn sn_sdk_time_refs(value: *mut Time) -> i32;
    fn sn_date_from_ymd(year: i64, month: i64, day: i64) -> *mut Date;
    fn sn_date_get_year(value: *mut Date) -> i64;
    fn sn_date_to_time(value: *mut Date) -> *mut std::ffi::c_void;
    fn sn_sdk_date_retain(value: *mut Date) -> *mut Date;
    fn sn_sdk_date_release(value: *mut Date);
    fn sn_sdk_date_refs(value: *mut Date) -> i32;
    fn free(value: *mut std::ffi::c_void);
}
fn main() {
    unsafe {
        let time = sn_time_from_millis(0);
        assert_eq!(sn_sdk_time_refs(time), 1);
        let alias = sn_sdk_time_retain(time);
        assert_eq!(alias, time);
        (*alias).milliseconds = 86_400_000;
        let text = sn_time_to_iso(time);
        sn_sdk_time_release(alias);
        sn_sdk_time_release(time);
        assert_eq!(CStr::from_ptr(text).to_bytes(), b"1970-01-02T00:00:00.000Z");
        free(text.cast());
        let date = sn_date_from_ymd(2024, 2, 29);
        assert_eq!(sn_sdk_date_refs(date), 1);
        let alias = sn_sdk_date_retain(date);
        assert_eq!(alias, date);
        (*alias).days = 0;
        assert_eq!(sn_date_get_year(date), 1970);
        let converted = sn_date_to_time(date).cast::<Time>();
        sn_sdk_date_release(alias);
        sn_sdk_date_release(date);
        assert_eq!((*converted).milliseconds, 0);
        assert_eq!(sn_sdk_time_refs(converted), 1);
        sn_sdk_time_release(converted);
    }
    println!("SDK canonical Time/Date Rust: pass");
}
