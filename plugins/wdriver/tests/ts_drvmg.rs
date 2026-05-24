use wdriver::driver::drvmg::*;

#[test]
// 驱动启动状态
pub fn unit_get_driven_stu() {
    let drivename: String = String::from("\\Hades\\HadesNet");
    let mut driverobj: DrivenManageImpl = DrivenManageImpl::new();
    let b: bool = driverobj.open_driver_handle(drivename);
    loop {
        if b == false {
            break;
        }
        // checkout handle invalid
        if driverobj.handle.is_invalid() {
            break;
        }

        break;
    }
}
