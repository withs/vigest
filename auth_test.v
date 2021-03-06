module vigest_auth

import net.http

fn test_md5() {
	mut config := http.FetchConfig{
		url: 'https://httpbin.org/digest-auth/auth/user/pass/MD5'
		method: .get
	}

	mut d_auth := new_digest_authentification('user', 'pass', config) or { return }
	mut rsp := d_auth.fetch() or { panic('$err') }

	assert rsp.status_code == 200
}

fn test_sha_256() {
	mut config := http.FetchConfig{
		url: 'https://httpbin.org/digest-auth/auth/user/pass/SHA-256'
		method: .get
	}

	mut d_auth := new_digest_authentification('user', 'pass', config) or { return }
	mut rsp := d_auth.fetch() or { panic('$err') }

	assert rsp.status_code == 200
}

fn test_sha_512() {
	mut config := http.FetchConfig{
		url: 'https://httpbin.org/digest-auth/auth/user/pass/SHA-512'
		method: .get
	}

	mut d_auth := new_digest_authentification('user', 'pass', config) or { return }
	mut rsp := d_auth.fetch() or { panic('$err') }

	assert rsp.status_code == 200
}
