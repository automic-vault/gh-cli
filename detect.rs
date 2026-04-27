use std::path::PathBuf;

pub fn install_is_insecure() -> Result<bool, String> {
    let hosts_paths = gh_hosts_paths()?;
    for path in &hosts_paths {
        if !path.exists() {
            continue;
        }
        let contents = std::fs::read_to_string(&path)
            .map_err(|err| format!("failed to read {}: {err}", path.display()))?;
        if contains_gh_auth_material(&contents) {
            return Ok(true);
        }
    }

    if keychain_allows_security_tool(&hosts_paths)? {
        return Ok(true);
    }

    Ok(false)
}

fn gh_hosts_paths() -> Result<Vec<PathBuf>, String> {
    if let Some(config_dir) = std::env::var_os("GH_CONFIG_DIR").filter(|value| !value.is_empty()) {
        return Ok(vec![PathBuf::from(config_dir).join("hosts.yml")]);
    }

    let mut paths = Vec::new();
    if let Some(config_home) = std::env::var_os("XDG_CONFIG_HOME").filter(|value| !value.is_empty())
    {
        paths.push(PathBuf::from(config_home).join("gh/hosts.yml"));
    }

    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| "HOME is not set".to_string())?;
    paths.push(home.join(".config/gh/hosts.yml"));
    Ok(paths)
}

fn contains_gh_auth_material(contents: &str) -> bool {
    contents.lines().any(|line| {
        let trimmed = line.trim();
        let Some((key, value)) = trimmed.split_once(':') else {
            return false;
        };
        matches!(key.trim(), "oauth_token" | "user")
            && !value.trim().is_empty()
            && value.trim() != "null"
    })
}

fn gh_keychain_services(hosts_paths: &[PathBuf]) -> Vec<String> {
    let mut services = vec!["gh:github.com".to_string()];
    for path in hosts_paths {
        let Ok(contents) = std::fs::read_to_string(path) else {
            continue;
        };
        for line in contents.lines() {
            if line.starts_with(char::is_whitespace) {
                continue;
            }
            let Some(host) = line.trim().strip_suffix(':') else {
                continue;
            };
            if host.is_empty() || host == "hosts" {
                continue;
            }
            services.push(format!("gh:{host}"));
        }
    }
    services.sort();
    services.dedup();
    services
}

#[cfg(target_os = "macos")]
fn keychain_allows_security_tool(hosts_paths: &[PathBuf]) -> Result<bool, String> {
    macos_keychain::keychain_allows_security_tool(&gh_keychain_services(hosts_paths))
}

#[cfg(not(target_os = "macos"))]
fn keychain_allows_security_tool(_hosts_paths: &[PathBuf]) -> Result<bool, String> {
    Ok(false)
}

#[cfg(target_os = "macos")]
mod macos_keychain {
    use std::ffi::c_void;
    use std::ptr;

    const ERR_SEC_SUCCESS: i32 = 0;
    const ERR_SEC_ITEM_NOT_FOUND: i32 = -25300;
    const CF_NUMBER_SINT32_TYPE: i32 = 3;
    const CSSM_ACL_AUTHORIZATION_ANY: i32 = 1;
    const CSSM_ACL_AUTHORIZATION_DECRYPT: i32 = 24;
    const SEC_GENERIC_PASSWORD_ITEM_CLASS: u32 = u32::from_be_bytes(*b"genp");
    const SEC_SERVICE_ITEM_ATTR: u32 = u32::from_be_bytes(*b"svce");
    const SECURITY_TOOL_PATH: &[u8] = b"/usr/bin/security";

    type CFTypeRef = *const c_void;
    type CFArrayRef = *const c_void;
    type CFDataRef = *const c_void;
    type CFNumberRef = *const c_void;
    type CFStringRef = *const c_void;
    type SecAccessRef = *const c_void;
    type SecACLRef = *const c_void;
    type SecKeychainItemRef = *const c_void;
    type SecKeychainSearchRef = *const c_void;
    type SecTrustedApplicationRef = *const c_void;

    #[repr(C)]
    struct SecKeychainAttribute {
        tag: u32,
        length: u32,
        data: *mut c_void,
    }

    #[repr(C)]
    struct SecKeychainAttributeList {
        count: u32,
        attr: *mut SecKeychainAttribute,
    }

    unsafe extern "C" {
        fn CFArrayGetCount(array: CFArrayRef) -> isize;
        fn CFArrayGetValueAtIndex(array: CFArrayRef, index: isize) -> *const c_void;
        fn CFDataGetBytePtr(data: CFDataRef) -> *const u8;
        fn CFDataGetLength(data: CFDataRef) -> isize;
        fn CFNumberGetValue(number: CFNumberRef, the_type: i32, value_ptr: *mut c_void) -> bool;
        fn CFRelease(value: CFTypeRef);
        fn SecACLCopyAuthorizations(acl: SecACLRef) -> CFArrayRef;
        fn SecACLCopyContents(
            acl: SecACLRef,
            application_list: *mut CFArrayRef,
            description: *mut CFStringRef,
            prompt_selector: *mut u16,
        ) -> i32;
        fn SecAccessCopyACLList(access: SecAccessRef, acl_list: *mut CFArrayRef) -> i32;
        fn SecKeychainItemCopyAccess(
            item: SecKeychainItemRef,
            access: *mut SecAccessRef,
        ) -> i32;
        fn SecKeychainSearchCopyNext(
            search: SecKeychainSearchRef,
            item: *mut SecKeychainItemRef,
        ) -> i32;
        fn SecKeychainSearchCreateFromAttributes(
            keychain_or_array: CFTypeRef,
            item_class: u32,
            attr_list: *const SecKeychainAttributeList,
            search: *mut SecKeychainSearchRef,
        ) -> i32;
        fn SecTrustedApplicationCopyData(
            app: SecTrustedApplicationRef,
            data: *mut CFDataRef,
        ) -> i32;
    }

    pub(super) fn keychain_allows_security_tool(services: &[String]) -> Result<bool, String> {
        for service in services {
            if service_allows_security_tool(service)? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn service_allows_security_tool(service: &str) -> Result<bool, String> {
        let mut service_bytes = service.as_bytes().to_vec();
        let mut attr = SecKeychainAttribute {
            tag: SEC_SERVICE_ITEM_ATTR,
            length: service_bytes.len() as u32,
            data: service_bytes.as_mut_ptr().cast(),
        };
        let attr_list = SecKeychainAttributeList {
            count: 1,
            attr: &mut attr,
        };
        let mut search = ptr::null();
        let status = unsafe {
            SecKeychainSearchCreateFromAttributes(
                ptr::null(),
                SEC_GENERIC_PASSWORD_ITEM_CLASS,
                &attr_list,
                &mut search,
            )
        };
        if status == ERR_SEC_ITEM_NOT_FOUND {
            return Ok(false);
        }
        check_status(status, "create keychain search")?;
        let _search_ref = ScopedCf(search);

        loop {
            let mut item = ptr::null();
            let status = unsafe { SecKeychainSearchCopyNext(search, &mut item) };
            if status == ERR_SEC_ITEM_NOT_FOUND {
                return Ok(false);
            }
            check_status(status, "copy next keychain item")?;
            let _item_ref = ScopedCf(item);
            if item_allows_security_tool(item)? {
                return Ok(true);
            }
        }
    }

    fn item_allows_security_tool(item: SecKeychainItemRef) -> Result<bool, String> {
        let mut access = ptr::null();
        let status = unsafe { SecKeychainItemCopyAccess(item, &mut access) };
        check_status(status, "copy keychain item access")?;
        let _access_ref = ScopedCf(access);

        let mut acl_list = ptr::null();
        let status = unsafe { SecAccessCopyACLList(access, &mut acl_list) };
        check_status(status, "copy keychain ACL list")?;
        let _acl_list_ref = ScopedCf(acl_list);

        let acl_count = unsafe { CFArrayGetCount(acl_list) };
        for index in 0..acl_count {
            let acl = unsafe { CFArrayGetValueAtIndex(acl_list, index).cast::<c_void>() };
            if acl.is_null() {
                continue;
            }
            if acl_allows_security_tool(acl)? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn acl_allows_security_tool(acl: SecACLRef) -> Result<bool, String> {
        if !acl_authorizes_secret_read(acl) {
            return Ok(false);
        }

        let mut app_list = ptr::null();
        let mut description = ptr::null();
        let mut prompt_selector = 0u16;
        let status = unsafe {
            SecACLCopyContents(acl, &mut app_list, &mut description, &mut prompt_selector)
        };
        check_status(status, "copy keychain ACL contents")?;
        let _description_ref = ScopedCf(description);
        if app_list.is_null() {
            return Ok(false);
        }
        let _app_list_ref = ScopedCf(app_list);

        let app_count = unsafe { CFArrayGetCount(app_list) };
        for index in 0..app_count {
            let app = unsafe { CFArrayGetValueAtIndex(app_list, index).cast::<c_void>() };
            if app.is_null() {
                continue;
            }
            if trusted_application_is_security_tool(app)? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn acl_authorizes_secret_read(acl: SecACLRef) -> bool {
        let authorizations = unsafe { SecACLCopyAuthorizations(acl) };
        if authorizations.is_null() {
            return false;
        }
        let _authorizations_ref = ScopedCf(authorizations);

        let authorization_count = unsafe { CFArrayGetCount(authorizations) };
        for index in 0..authorization_count {
            let authorization =
                unsafe { CFArrayGetValueAtIndex(authorizations, index).cast::<c_void>() };
            if authorization.is_null() {
                continue;
            }
            if authorization_grants_secret_read(authorization) {
                return true;
            }
        }
        false
    }

    fn authorization_grants_secret_read(authorization: CFNumberRef) -> bool {
        let mut tag = 0i32;
        let ok = unsafe {
            CFNumberGetValue(
                authorization,
                CF_NUMBER_SINT32_TYPE,
                (&mut tag as *mut i32).cast(),
            )
        };
        ok && auth_tag_grants_secret_read(tag)
    }

    fn auth_tag_grants_secret_read(tag: i32) -> bool {
        tag == CSSM_ACL_AUTHORIZATION_DECRYPT || tag == CSSM_ACL_AUTHORIZATION_ANY
    }

    fn trusted_application_is_security_tool(app: SecTrustedApplicationRef) -> Result<bool, String> {
        let mut data = ptr::null();
        let status = unsafe { SecTrustedApplicationCopyData(app, &mut data) };
        check_status(status, "copy trusted application data")?;
        let _data_ref = ScopedCf(data);

        let bytes = cf_data_bytes(data);
        Ok(bytes
            .windows(SECURITY_TOOL_PATH.len())
            .any(|window| window == SECURITY_TOOL_PATH))
    }

    fn cf_data_bytes(data: CFDataRef) -> Vec<u8> {
        let length = unsafe { CFDataGetLength(data) };
        if length <= 0 {
            return Vec::new();
        }
        let ptr = unsafe { CFDataGetBytePtr(data) };
        if ptr.is_null() {
            return Vec::new();
        }
        unsafe { std::slice::from_raw_parts(ptr, length as usize).to_vec() }
    }

    fn check_status(status: i32, context: &str) -> Result<(), String> {
        if status == ERR_SEC_SUCCESS {
            Ok(())
        } else {
            Err(format!("{context} failed with OSStatus {status}"))
        }
    }

    struct ScopedCf<T>(*const T);

    impl<T> Drop for ScopedCf<T> {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe { CFRelease(self.0.cast()) };
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn read_authorization_tags_cover_decrypt_and_any_only() {
            assert!(auth_tag_grants_secret_read(CSSM_ACL_AUTHORIZATION_DECRYPT));
            assert!(auth_tag_grants_secret_read(CSSM_ACL_AUTHORIZATION_ANY));
            assert!(!auth_tag_grants_secret_read(0));
        }
    }
}
