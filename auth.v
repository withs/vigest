module vigest_auth

import net.http
import net.urllib
import encoding.base64
import crypto.md5
import crypto.rand
import crypto.sha256
import crypto.sha512

pub enum HashMethod {
	md5
	md5_sess
	sha256
	sha256_sess
	sha512
	sha512_256_sess
	unknown
}

pub fn (h HashMethod) str() string {
	match h {
		.md5 { return 'MD5' }
		.md5_sess { return 'MD5-sess' }
		.sha256 { return 'SHA-256' }
		.sha256_sess { return 'SHA-256-sess' }
		.sha512 { return 'SHA-512' }
		.sha512_256_sess { return 'SHA-512-256-sess' }
		.unknown { return 'unknown' }
	}
}

pub fn hash_method_from_str(withValue string) HashMethod {
	match withValue {
		'MD5-sess' { return .md5_sess }
		'MD5' { return .md5 }
		'SHA-256' { return .sha256 }
		'SHA-256-sess' { return .sha256_sess }
		'SHA-512' { return .sha512 }
		'SHA-512-256-sess' { return .sha512_256_sess }
		else { return .unknown }
	}
}

pub enum Qop {
	auth
	auth_int
	unknown
}

pub fn (q Qop) str() string {
	match q {
		.auth { return 'auth' }
		.auth_int { return 'auth-int' }
		.unknown { return 'unknown' }
	}
}

pub fn qop_from_str(withValue string) Qop {
	match withValue {
		'auth' { return .auth }
		'auth-int' { return .auth_int }
		else { return .unknown }
	}
}

pub struct DigestAuthentification {
pub mut:
	username    string
	password    string
	request     http.FetchConfig
	request_url urllib.URL

	qop       Qop        = .unknown
	algorithm HashMethod = .md5
	realm     string
	nonce     string
	stale     bool
	opaque    string
	nc        int
	cnonce    string
}

fn (d DigestAuthentification) have_required_fields() bool {
	if d.algorithm == .unknown || d.realm.len == 0 || d.nonce.len == 0 {
		return false
	}
	return true
}

fn (d DigestAuthentification) hash(withValue string) string {
	// dump(withValue)
	match d.algorithm {
		.md5 {
			return md5.hexhash(withValue)
		}
		.md5_sess {
			return md5.hexhash(withValue)
		}
		.sha256 {
			return sha256.hexhash(withValue)
		}
		.sha256_sess {
			return sha256.hexhash(withValue)
		}
		.sha512 {
			return sha512.hexhash(withValue)
		}
		.sha512_256_sess {
			return sha512.hexhash(withValue)
		}
		.unknown { // it should never hit this because we set earlier that the default alogrithm is md5
			return md5.hexhash(withValue)
		}
	}
}

fn (mut d DigestAuthentification) parse_www_authentificate_header(withValue string) {

	a := 'Digest qop="auth",algorithm=MD5,realm="monero-rpc",nonce="mXGqDmo9MY6hFgDK0kT/sw==",stale=true'
	without_digest := a.all_after('Digest ')
	raw_fields := without_digest.split(',')
	fields := raw_fields.map(fn (s string) []string {
		mut parsed_res := []string{}

		mut key := s.all_before('=')

		if key.contains(' ') {
			key = key.replace(' ', '')
		}

		parsed_res << key

		mut value := s.all_after('=')

		if value.contains('"') {
			value = value.find_between('"', '"')
		}

		parsed_res << value

		return parsed_res
	})

	for field in fields {
		key := field[0]
		value := field[1]

		match key {
			'qop' { d.qop = qop_from_str(value) }
			'algorithm' { d.algorithm = hash_method_from_str(value) }
			'realm' { d.realm = value }
			'nonce' { d.nonce = value }
			'stale' { d.stale = value.bool() }
			'opaque' { d.opaque = value }
			else { continue }
		}
	}
}

fn (mut d DigestAuthentification) generate_cnonce() {
	// FIXME: Not very secure ^^
	d.cnonce = base64.encode_str(md5.hexhash(rand.int_u64(667670123) or { 1 }.str()))
}

fn (mut d DigestAuthentification) build_challenge_solution() ?string {
	if d.qop != .unknown {
		d.generate_cnonce()
	}

	mut fst_hash := ''

	if d.algorithm == .md5_sess || d.algorithm == .sha256_sess || d.algorithm == .sha512_256_sess {
		pre_hash := d.hash('$d.username:$d.realm:$d.password')
		fst_hash = d.hash('$pre_hash:$d.nonce:$d.cnonce')
	} else {
		fst_hash = d.hash('$d.username:$d.realm:$d.password')
	}

	mut sec_hash := ''

	if d.qop == .auth || d.qop == .unknown {
		sec_hash = d.hash('$d.request.method.str():$d.request_url.path')
	} else if d.qop == .auth_int {
		pst_hash := d.hash(d.request.data)
		sec_hash = d.hash('$d.request.method.str():$d.request_url.path:$pst_hash')
	} else {
		return error('Unimplemented qop')
	}

	mut solution := ''

	if d.qop == .auth || d.qop == .auth_int {
		solution = d.hash('$fst_hash:$d.nonce:$d.nc.hex_full():$d.cnonce:$d.qop.str():$sec_hash')
	} else {
		solution = d.hash('$fst_hash:$d.nonce:$sec_hash')
	}

	mut auth := 'Digest '

	// always present
	auth += 'username="$d.username", '
	auth += 'realm="$d.realm", '
	auth += 'nonce="$d.nonce", '
	auth += 'uri="$d.request_url.path", '
	auth += 'response="$solution", '

	// not always present
	if d.opaque.len != 0 {
		auth += 'opaque="$d.opaque", '
	}

	if d.qop != .unknown {
		auth += 'cnonce="$d.cnonce", '
		auth += 'nc=$d.nc.hex_full(), '
		auth += 'qop=$d.qop.str(), '
	}

	// always present but it dont have the "," at the end
	auth += 'algorithm=$d.algorithm.str()'
	dump(auth)
	return auth
}

pub fn (mut d DigestAuthentification) fetch() ?http.Response {
	d.request.header.delete(.connection)
	d.request.header.add(.connection, "Keep-Alive")

	req_challenge := http.fetch(d.request) or {
		return error('Error while reqesting auth challenge: $err')
	}

	// dump(req_challenge)

	// i could check if the status code is 401 or 407 but the request only return a challenge in the header www_authenticate when you'r not authenticated

	poss_challenges := req_challenge.header.values(.www_authenticate)

	if poss_challenges.len == 0 {
		return error("No challenge found are you sure it's a Digest auth ?")
	}

	// some service provide multiple www_authenticate but we'll take the first one

	d.parse_www_authentificate_header(poss_challenges[0])

	if !d.have_required_fields() {
		return error('Some essential field are missing')
	}

	if d.qop != .unknown {
		d.nc++
	}

	challenge_solution := d.build_challenge_solution() or {
		return error('Failed to solve challenge $err')
	}

	d.request.header.add(.authorization, challenge_solution)
/*
	// retrying request with solution
	resp := http.fetch(d.request) or {
		return error('Error while proceeding request with solution: $err')
	}
*/
	return none
}

pub fn new_digest_authentification(withUsername string, andPassword string, forFetchConfig http.FetchConfig) ?DigestAuthentification {
	mut d_auth := DigestAuthentification{
		username: withUsername
		password: andPassword
		request: forFetchConfig
	}

	d_auth.request_url = urllib.parse(d_auth.request.url) or {
		return error('It seems that the url given is invalid and cannot be parsed: $err')
	}

	return d_auth
}
