//go:build ignore
// +build ignore

/*
 * Copyright 2018-2023, CS Systemes d'Information, http://csgroup.eu
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package gorules

import "github.com/quasilyte/go-ruleguard/dsl"

// This is a collection of rules for ruleguard: https://github.com/quasilyte/go-ruleguard
func repairs1(m dsl.Matcher) {
	m.Import("github.com/CS-SI/SafeScale/v22/lib/utils/fail")

	m.Match("if xerr != nil { return $b }").
		Where((m["b"].Type.Is("error") || m["b"].Type.Is("fail.Error")) && !m["b"].Text.Matches(".*xerr.*")).
		Report("returning the wrong error?")
}

func repairs1b(m dsl.Matcher) {
	m.Import("github.com/CS-SI/SafeScale/v22/lib/utils/fail")

	m.Match("if err != nil { return $b }").
		Where((m["b"].Type.Is("error") || m["b"].Type.Is("fail.Error")) && !m["b"].Text.Matches(".*err.*")).
		Report("returning the wrong error?")
}

func repairs1c(m dsl.Matcher) {
	m.Import("github.com/CS-SI/SafeScale/v22/lib/utils/fail")

	m.Match("if innerXErr != nil { return $b }").
		Where((m["b"].Type.Is("error") || m["b"].Type.Is("fail.Error")) && !m["b"].Text.Matches(".*innerXErr.*")).
		Report("returning the wrong error?")
}

func repairs2(m dsl.Matcher) {
	m.Import("github.com/CS-SI/SafeScale/v22/lib/utils/fail")

	m.Match("if xerr != nil { return nil, $b }").
		Where((m["b"].Type.Is("error") || m["b"].Type.Is("fail.Error")) && !m["b"].Text.Matches(".*xerr.*")).
		Report("returning the wrong error?")
}

func repairs2b(m dsl.Matcher) {
	m.Import("github.com/CS-SI/SafeScale/v22/lib/utils/fail")

	m.Match("if err != nil { return nil, $b }").
		Where((m["b"].Type.Is("error") || m["b"].Type.Is("fail.Error")) && !m["b"].Text.Matches(".*err.*")).
		Report("returning the wrong error?")
}

func repairs2c(m dsl.Matcher) {
	m.Import("github.com/CS-SI/SafeScale/v22/lib/utils/fail")

	m.Match("if innerXErr != nil { return nil, $b }").
		Where((m["b"].Type.Is("error") || m["b"].Type.Is("fail.Error")) && !m["b"].Text.Matches(".*innerXErr.*")).
		Report("returning the wrong error?")
}

// Remove extra conversions: mdempsky/unconvert
func unconvert(m dsl.Matcher) {
	m.Match("int($x)").Where(m["x"].Type.Is("int") && !m["x"].Const).Report("unnecessary conversion").Suggest("$x")

	m.Match("float32($x)").Where(m["x"].Type.Is("float32") && !m["x"].Const).Report("unnecessary conversion").Suggest("$x")
	m.Match("float64($x)").Where(m["x"].Type.Is("float64") && !m["x"].Const).Report("unnecessary conversion").Suggest("$x")

	// m.Match("byte($x)").Where(m["x"].Type.Is("byte")).Report("unnecessary conversion").Suggest("$x")
	// m.Match("rune($x)").Where(m["x"].Type.Is("rune")).Report("unnecessary conversion").Suggest("$x")
	m.Match("bool($x)").Where(m["x"].Type.Is("bool") && !m["x"].Const).Report("unnecessary conversion").Suggest("$x")

	m.Match("int8($x)").Where(m["x"].Type.Is("int8") && !m["x"].Const).Report("unnecessary conversion").Suggest("$x")
	m.Match("int16($x)").Where(m["x"].Type.Is("int16") && !m["x"].Const).Report("unnecessary conversion").Suggest("$x")
	m.Match("int32($x)").Where(m["x"].Type.Is("int32") && !m["x"].Const).Report("unnecessary conversion").Suggest("$x")
	m.Match("int64($x)").Where(m["x"].Type.Is("int64") && !m["x"].Const).Report("unnecessary conversion").Suggest("$x")

	m.Match("uint8($x)").Where(m["x"].Type.Is("uint8") && !m["x"].Const).Report("unnecessary conversion").Suggest("$x")
	m.Match("uint16($x)").Where(m["x"].Type.Is("uint16") && !m["x"].Const).Report("unnecessary conversion").Suggest("$x")
	m.Match("uint32($x)").Where(m["x"].Type.Is("uint32") && !m["x"].Const).Report("unnecessary conversion").Suggest("$x")
	m.Match("uint64($x)").Where(m["x"].Type.Is("uint64") && !m["x"].Const).Report("unnecessary conversion").Suggest("$x")

	m.Match("time.Duration($x)").Where(m["x"].Type.Is("time.Duration") && !m["x"].Text.Matches("^[0-9]*$")).Report("unnecessary conversion").Suggest("$x")
}

// Don't use == or != with time.Time
// https://github.com/dominikh/go-tools/issues/47 : Wontfix
func timeeq(m dsl.Matcher) {
	m.Match("$t0 == $t1").Where(m["t0"].Type.Is("time.Time")).Report("using == with time.Time")
	m.Match("$t0 != $t1").Where(m["t0"].Type.Is("time.Time")).Report("using != with time.Time")
	m.Match(`map[$k]$v`).Where(m["k"].Type.Is("time.Time")).Report("map with time.Time keys are easy to misuse")
}

// err but no an error
func errnoterror(m dsl.Matcher) {
	// Would be easier to check for all err identifiers instead, but then how do we get the type from m[] ?
	m.Import("github.com/CS-SI/SafeScale/v22/lib/utils/fail")

	m.Match(
		"if $*_, err := $x; $err != nil { $*_ } else if $_ { $*_ }",
		"if $*_, err := $x; $err != nil { $*_ } else { $*_ }",
		"if $*_, err := $x; $err != nil { $*_ }",

		"if $*_, err = $x; $err != nil { $*_ } else if $_ { $*_ }",
		"if $*_, err = $x; $err != nil { $*_ } else { $*_ }",
		"if $*_, err = $x; $err != nil { $*_ }",

		"$*_, err := $x; if $err != nil { $*_ } else if $_ { $*_ }",
		"$*_, err := $x; if $err != nil { $*_ } else { $*_ }",
		"$*_, err := $x; if $err != nil { $*_ }",

		"$*_, err = $x; if $err != nil { $*_ } else if $_ { $*_ }",
		"$*_, err = $x; if $err != nil { $*_ } else { $*_ }",
		"$*_, err = $x; if $err != nil { $*_ }",
	).
		Where(m["err"].Text == "err" && !(m["err"].Type.Is("error") || m["err"].Type.Is("fail.Error")) && m["x"].Text != "recover()").
		Report("err variable not error type")
}

// err but no an error
func xerrnoterror(m dsl.Matcher) {
	// Would be easier to check for all err identifiers instead, but then how do we get the type from m[] ?
	m.Import("github.com/CS-SI/SafeScale/v22/lib/utils/fail")

	m.Match(
		"if $*_, xerr := $x; $xerr != nil { $*_ } else if $_ { $*_ }",
		"if $*_, xerr := $x; $xerr != nil { $*_ } else { $*_ }",
		"if $*_, xerr := $x; $xerr != nil { $*_ }",

		"if $*_, xerr = $x; $xerr != nil { $*_ } else if $_ { $*_ }",
		"if $*_, xerr = $x; $xerr != nil { $*_ } else { $*_ }",
		"if $*_, xerr = $x; $xerr != nil { $*_ }",

		"$*_, xerr := $x; if $xerr != nil { $*_ } else if $_ { $*_ }",
		"$*_, xerr := $x; if $xerr != nil { $*_ } else { $*_ }",
		"$*_, xerr := $x; if $xerr != nil { $*_ }",

		"$*_, xerr = $x; if $xerr != nil { $*_ } else if $_ { $*_ }",
		"$*_, xerr = $x; if $xerr != nil { $*_ } else { $*_ }",
		"$*_, xerr = $x; if $xerr != nil { $*_ }",
	).
		Where(m["xerr"].Text == "xerr" && !(m["xerr"].Type.Is("error") || m["xerr"].Type.Is("fail.Error")) && m["x"].Text != "recover()").
		Report("xerr variable not error type")
}

// Identical if and else bodies
func ifbodythenbody(m dsl.Matcher) {
	m.Match("if $*_ { $body } else { $body }").
		Report("identical if and else bodies")

	// Lots of false positives.
	// m.Match("if $*_ { $body } else if $*_ { $body }").
	//	Report("identical if and else bodies")
}

// Odd inequality: A - B < 0 instead of !=
// Too many false positives.
/*
func subtractnoteq(m dsl.Matcher) {
	m.Match("$a - $b < 0").Report("consider $a != $b")
	m.Match("$a - $b > 0").Report("consider $a != $b")
	m.Match("0 < $a - $b").Report("consider $a != $b")
	m.Match("0 > $a - $b").Report("consider $a != $b")
}
*/

// Self-assignment
func selfassign(m dsl.Matcher) {
	m.Match("$x = $x").Report("useless self-assignment")
}

// Odd nested ifs
func oddnestedif(m dsl.Matcher) {
	m.Match("if $x { if $x { $*_ }; $*_ }",
		"if $x == $y { if $x != $y {$*_ }; $*_ }",
		"if $x != $y { if $x == $y {$*_ }; $*_ }",
		"if $x { if !$x { $*_ }; $*_ }",
		"if !$x { if $x { $*_ }; $*_ }").
		Report("odd nested ifs")

	m.Match("for $x { if $x { $*_ }; $*_ }",
		"for $x == $y { if $x != $y {$*_ }; $*_ }",
		"for $x != $y { if $x == $y {$*_ }; $*_ }",
		"for $x { if !$x { $*_ }; $*_ }",
		"for !$x { if $x { $*_ }; $*_ }").
		Report("odd nested for/ifs")
}

// odd bitwise expressions
func oddbitwise(m dsl.Matcher) {
	m.Match("$x | $x",
		"$x | ^$x",
		"^$x | $x").
		Report("odd bitwise OR")

	m.Match("$x & $x",
		"$x & ^$x",
		"^$x & $x").
		Report("odd bitwise AND")

	m.Match("$x &^ $x").
		Report("odd bitwise AND-NOT")
}

// odd sequence of if tests with return
func ifreturn(m dsl.Matcher) {
	m.Match("if $x { return $*_ }; if $x {$*_ }").Report("odd sequence of if test")
	m.Match("if $x { return $*_ }; if !$x {$*_ }").Report("odd sequence of if test")
	m.Match("if !$x { return $*_ }; if $x {$*_ }").Report("odd sequence of if test")
	m.Match("if $x == $y { return $*_ }; if $x != $y {$*_ }").Report("odd sequence of if test")
	m.Match("if $x != $y { return $*_ }; if $x == $y {$*_ }").Report("odd sequence of if test")

}

func oddifsequence(m dsl.Matcher) {
	m.Match("if $x { $*_ }; if $x {$*_ }").Report("odd sequence of if test")

	m.Match("if $x == $y { $*_ }; if $y == $x {$*_ }").Report("odd sequence of if tests")
	m.Match("if $x != $y { $*_ }; if $y != $x {$*_ }").Report("odd sequence of if tests")

	m.Match("if $x < $y { $*_ }; if $y > $x {$*_ }").Report("odd sequence of if tests")
	m.Match("if $x <= $y { $*_ }; if $y >= $x {$*_ }").Report("odd sequence of if tests")

	m.Match("if $x > $y { $*_ }; if $y < $x {$*_ }").Report("odd sequence of if tests")
	m.Match("if $x >= $y { $*_ }; if $y <= $x {$*_ }").Report("odd sequence of if tests")
}

// odd sequence of nested if tests
func nestedifsequence(m dsl.Matcher) {
	m.Match("if $x < $y { if $x >= $y {$*_ }; $*_ }").Report("odd sequence of nested if tests")
	m.Match("if $x <= $y { if $x > $y {$*_ }; $*_ }").Report("odd sequence of nested if tests")
	m.Match("if $x > $y { if $x <= $y {$*_ }; $*_ }").Report("odd sequence of nested if tests")
	m.Match("if $x >= $y { if $x < $y {$*_ }; $*_ }").Report("odd sequence of nested if tests")

}

// odd sequence of assignments
func identicalassignments(m dsl.Matcher) {
	m.Match("$x  = $y; $y = $x").Report("odd sequence of assignments")
}

func oddcompoundop(m dsl.Matcher) {
	m.Match("$x += $x + $_",
		"$x += $x - $_").
		Report("odd += expression")

	m.Match("$x -= $x + $_",
		"$x -= $x - $_").
		Report("odd -= expression")
}

func constswitch(m dsl.Matcher) {
	m.Match("switch $x { $*_ }", "switch $*_; $x { $*_ }").
		Where(m["x"].Const && !m["x"].Text.Matches(`^runtime\.`)).
		Report("constant switch")
}

func oddcomparisons(m dsl.Matcher) {
	m.Match(
		"$x - $y == 0",
		"$x - $y != 0",
		"$x - $y < 0",
		"$x - $y <= 0",
		"$x - $y > 0",
		"$x - $y >= 0",
		"$x ^ $y == 0",
		"$x ^ $y != 0",
	).Report("odd comparison")
}

func oddmathbits(m dsl.Matcher) {
	m.Match(
		"64 - bits.LeadingZeros64($x)",
		"32 - bits.LeadingZeros32($x)",
		"16 - bits.LeadingZeros16($x)",
		"8 - bits.LeadingZeros8($x)",
	).Report("odd math/bits expression: use bits.Len*() instead?")
}

func floateq(m dsl.Matcher) {
	m.Match(
		"$x == $y",
		"$x != $y",
	).
		Where(m["x"].Type.Is("float32") && !m["x"].Const && !m["y"].Text.Matches("0(.0+)?")).
		Report("floating point tested for equality")

	m.Match(
		"$x == $y",
		"$x != $y",
	).
		Where(m["x"].Type.Is("float64") && !m["x"].Const && !m["y"].Text.Matches("0(.0+)?")).
		Report("floating point tested for equality")

	m.Match("switch $x { $*_ }", "switch $*_; $x { $*_ }").
		Where(m["x"].Type.Is("float32")).
		Report("floating point as switch expression")

	m.Match("switch $x { $*_ }", "switch $*_; $x { $*_ }").
		Where(m["x"].Type.Is("float64")).
		Report("floating point as switch expression")

}

func badexponent(m dsl.Matcher) {
	m.Match(
		"2 ^ $x",
		"10 ^ $x",
	).
		Report("caret (^) is not exponentiation")
}

func floatloop(m dsl.Matcher) {
	m.Match(
		"for $i := $x; $i < $y; $i += $z { $*_ }",
		"for $i = $x; $i < $y; $i += $z { $*_ }",
	).
		Where(m["i"].Type.Is("float64")).
		Report("floating point for loop counter")

	m.Match(
		"for $i := $x; $i < $y; $i += $z { $*_ }",
		"for $i = $x; $i < $y; $i += $z { $*_ }",
	).
		Where(m["i"].Type.Is("float32")).
		Report("floating point for loop counter")
}

func urlredacted(m dsl.Matcher) {

	m.Match(
		"log.Println($x, $*_)",
		"log.Println($*_, $x, $*_)",
		"log.Println($*_, $x)",
		"log.Printf($*_, $x, $*_)",
		"log.Printf($*_, $x)",

		"log.Println($x, $*_)",
		"log.Println($*_, $x, $*_)",
		"log.Println($*_, $x)",
		"log.Printf($*_, $x, $*_)",
		"log.Printf($*_, $x)",
	).
		Where(m["x"].Type.Is("*url.URL")).
		Report("consider $x.Redacted() when outputting URLs")
}

func sprinterr(m dsl.Matcher) {
	m.Match(`fmt.Sprint($err)`,
		`fmt.Sprintf("%s", $err)`,
		`fmt.Sprintf("%v", $err)`,
	).
		Where(m["err"].Type.Is("error")).
		Report("maybe call $err.Error() instead of fmt.Sprint()?")
}

func largeloopcopy(m dsl.Matcher) {
	m.Match(
		`for $_, $v := range $_ { $*_ }`,
	).
		Where(m["v"].Type.Size > 512).
		Report(`loop copies large value each iteration`)
}

func joinpath(m dsl.Matcher) {
	m.Match(
		`strings.Join($_, "/")`,
		`strings.Join($_, "\\")`,
		"strings.Join($_, `\\`)",
	).
		Report(`did you mean path.Join() or filepath.Join() ?`)
}

func readfull(m dsl.Matcher) {
	m.Match(`$n, $err := io.ReadFull($_, $slice)
                 if $err != nil || $n != len($slice) {
                              $*_
		 }`,
		`$n, $err := io.ReadFull($_, $slice)
                 if $n != len($slice) || $err != nil {
                              $*_
		 }`,
		`$n, $err = io.ReadFull($_, $slice)
                 if $err != nil || $n != len($slice) {
                              $*_
		 }`,
		`$n, $err = io.ReadFull($_, $slice)
                 if $n != len($slice) || $err != nil {
                              $*_
		 }`,
		`if $n, $err := io.ReadFull($_, $slice); $n != len($slice) || $err != nil {
                              $*_
		 }`,
		`if $n, $err := io.ReadFull($_, $slice); $err != nil || $n != len($slice) {
                              $*_
		 }`,
		`if $n, $err = io.ReadFull($_, $slice); $n != len($slice) || $err != nil {
                              $*_
		 }`,
		`if $n, $err = io.ReadFull($_, $slice); $err != nil || $n != len($slice) {
                              $*_
		 }`,
	).Report("io.ReadFull() returns err == nil iff n == len(slice)")
}

func nilerr(m dsl.Matcher) {
	m.Match(
		`if err == nil { return err }`,
		`if err == nil { return $*_, err }`,
	).
		Report(`return nil error instead of nil value`)
}

func nilxerr(m dsl.Matcher) {
	m.Match(
		`if xerr == nil { return xerr }`,
		`if xerr == nil { return $*_, xerr }`,
	).
		Report(`return nil error instead of nil value`)
}

func mailaddress(m dsl.Matcher) {
	m.Match(
		"fmt.Sprintf(`\"%s\" <%s>`, $NAME, $EMAIL)",
		"fmt.Sprintf(`\"%s\"<%s>`, $NAME, $EMAIL)",
		"fmt.Sprintf(`%s <%s>`, $NAME, $EMAIL)",
		"fmt.Sprintf(`%s<%s>`, $NAME, $EMAIL)",
		`fmt.Sprintf("\"%s\"<%s>", $NAME, $EMAIL)`,
		`fmt.Sprintf("\"%s\" <%s>", $NAME, $EMAIL)`,
		`fmt.Sprintf("%s<%s>", $NAME, $EMAIL)`,
		`fmt.Sprintf("%s <%s>", $NAME, $EMAIL)`,
	).
		Report("use net/mail Address.String() instead of fmt.Sprintf()").
		Suggest("(&mail.Address{Name:$NAME, Address:$EMAIL}).String()")

}

func errnetclosed(m dsl.Matcher) {
	m.Match(
		`strings.Contains($err.Error(), $text)`,
	).
		Where(m["text"].Text.Matches("\".*closed network connection.*\"")).
		Report(`String matching against error texts is fragile; use net.ErrClosed instead`).
		Suggest(`errors.Is($err, net.ErrClosed)`)

}

func hmacnew(m dsl.Matcher) {
	m.Match("hmac.New(func() hash.Hash { return $x }, $_)",
		`$f := func() hash.Hash { return $x }
	$*_
	hmac.New($f, $_)`,
	).Where(m["x"].Pure).
		Report("invalid hash passed to hmac.New()")
}

func readeof(m dsl.Matcher) {
	m.Match(
		`$n, $err = $r.Read($_)
	if $err != nil {
	    return $*_
	}`,
		`$n, $err := $r.Read($_)
	if $err != nil {
	    return $*_
	}`).Where(m["r"].Type.Implements("io.Reader")).
		Report("Read() can return n bytes and io.EOF")
}

func writestring(m dsl.Matcher) {
	m.Match(`io.WriteString($w, string($b))`).
		Where(m["b"].Type.Is("[]byte")).
		Suggest("$w.Write($b)")
}

func badlock(m dsl.Matcher) {
	// Shouldn't give many false positives without type filter
	// as Lock+Unlock pairs in combination with defer gives us pretty
	// a good chance to guess correctly. If we constrain the type to sync.Mutex
	// then it'll be harder to match embedded locks and custom methods
	// that may forward the call to the sync.Mutex (or other synchronization primitive).

	m.Match(`$mu.Lock(); defer $mu.RUnlock()`).Report(`maybe $mu.RLock() was intended?`)
	m.Match(`$mu.RLock(); defer $mu.Unlock()`).Report(`maybe $mu.Lock() was intended?`)

	// `mu1` and `mu2` are added to make possible report a line where `m2` is used (with a defer)
	m.Match(`$mu1.Lock(); defer $mu2.Lock()`).
		Where(m["mu1"].Text == m["mu2"].Text).
		At(m["mu2"]).
		Report(`maybe defer $mu1.Unlock() was intended?`)
	m.Match(`$mu1.RLock(); defer $mu2.RLock()`).
		Where(m["mu1"].Text == m["mu2"].Text).
		At(m["mu2"]).
		Report(`maybe defer $mu1.RUnlock() was intended?`)
}

func lockchain(m dsl.Matcher) {
	m.Match(`$mu.Lock(); $*_; $mu.Lock()`).Report(`maybe $mu.Unlock() was intended?`)
	m.Match(`$mu.RLock(); $*_; $mu.RLock()`).Report(`maybe $mu.RUnLock() was intended?`)
	m.Match(`$mu.localcache.Lock(); $*_; $mu.localcache.Lock()`).Report(`maybe $mu.localcache.Unlock() was intended?`)
	m.Match(`$mu.localcache.RLock(); $*_; $mu.localcache.RLock()`).Report(`maybe $mu.localcache.RUnLock() was intended?`)
}

func nodefer(m dsl.Matcher) {
	m.Match(`$mu.Lock(); $mu.Unlock()`).Report(`maybe you forgot a defer for $mu.Unlock() ?`)
	m.Match(`$mu.RLock(); $mu.RUnlock()`).Report(`maybe you forgot a defer for $mu.RUnlock() ?`)
	m.Match(`$mu.localcache.Lock(); $mu.localcache.Unlock()`).Report(`maybe you forgot a defer for $mu.localcache.Unlock() ?`)
	m.Match(`$mu.localcache.RLock(); $mu.localcache.RUnlock()`).Report(`maybe you forgot a defer $mu.localcache.RUnlock() ?`)
}

func contextTODO(m dsl.Matcher) {
	m.Match(`context.TODO()`).Report(`consider to use well-defined context`)
}

func wrongerrcall(m dsl.Matcher) {
	m.Match(
		`if $x.Err() != nil { return err }`,
		`if $x.Err() != nil { return $*_, err }`,
	).
		Report(`maybe returning wrong error after Err() call`)
}

func BucketDanger(m dsl.Matcher) {
	m.Import("github.com/CS-SI/SafeScale/v22/lib/backend/resources")
	m.Match(`$x.Alter($*_)`, `$x.BrowseFolder($*_)`, `$x.Deserialize($*_)`, `$x.GetService($*_)`, `$x.Inspect($*_)`, `$x.Review($*_)`, `$x.Read($*_)`, `$x.ReadByID($*_)`, `$x.Reload($*_)`, `$x.Serialize($*_)`).Where(m["x"].Type.Is("resources.bucket")).Report(`panic danger`)
}

func ClusterDanger(m dsl.Matcher) {
	m.Import("github.com/CS-SI/SafeScale/v22/lib/backend/resources")
	m.Match(`$x.Alter($*_)`, `$x.BrowseFolder($*_)`, `$x.Deserialize($*_)`, `$x.GetService($*_)`, `$x.Inspect($*_)`, `$x.Review($*_)`, `$x.Read($*_)`, `$x.ReadByID($*_)`, `$x.Reload($*_)`, `$x.Serialize($*_)`).Where(m["x"].Type.Is("resources.cluster")).Report(`panic danger`)
}

func HostDanger(m dsl.Matcher) {
	m.Import("github.com/CS-SI/SafeScale/v22/lib/backend/resources")
	m.Match(`$x.Alter($*_)`, `$x.BrowseFolder($*_)`, `$x.Deserialize($*_)`, `$x.GetService($*_)`, `$x.Inspect($*_)`, `$x.Review($*_)`, `$x.Read($*_)`, `$x.ReadByID($*_)`, `$x.Reload($*_)`, `$x.Serialize($*_)`).Where(m["x"].Type.Is("resources.host")).Report(`panic danger`)
}

func NetworkDanger(m dsl.Matcher) {
	m.Import("github.com/CS-SI/SafeScale/v22/lib/backend/resources")
	m.Match(`$x.Alter($*_)`, `$x.BrowseFolder($*_)`, `$x.Deserialize($*_)`, `$x.GetService($*_)`, `$x.Inspect($*_)`, `$x.Review($*_)`, `$x.Read($*_)`, `$x.ReadByID($*_)`, `$x.Reload($*_)`, `$x.Serialize($*_)`).Where(m["x"].Type.Is("resources.network")).Report(`panic danger`)
}

func SGDanger(m dsl.Matcher) {
	m.Import("github.com/CS-SI/SafeScale/v22/lib/backend/resources")
	m.Match(`$x.Alter($*_)`, `$x.BrowseFolder($*_)`, `$x.Deserialize($*_)`, `$x.GetService($*_)`, `$x.Inspect($*_)`, `$x.Review($*_)`, `$x.Read($*_)`, `$x.ReadByID($*_)`, `$x.Reload($*_)`, `$x.Serialize($*_)`).Where(m["x"].Type.Is("resources.securitygroup")).Report(`panic danger`)
}

func ShareDanger(m dsl.Matcher) {
	m.Import("github.com/CS-SI/SafeScale/v22/lib/backend/resources")
	m.Match(`$x.Alter($*_)`, `$x.BrowseFolder($*_)`, `$x.Deserialize($*_)`, `$x.GetService($*_)`, `$x.Inspect($*_)`, `$x.Review($*_)`, `$x.Read($*_)`, `$x.ReadByID($*_)`, `$x.Reload($*_)`, `$x.Serialize($*_)`).Where(m["x"].Type.Is("resources.share")).Report(`panic danger`)
}

func SubnetDanger(m dsl.Matcher) {
	m.Import("github.com/CS-SI/SafeScale/v22/lib/backend/resources")
	m.Match(`$x.Alter($*_)`, `$x.BrowseFolder($*_)`, `$x.Deserialize($*_)`, `$x.GetService($*_)`, `$x.Inspect($*_)`, `$x.Review($*_)`, `$x.Read($*_)`, `$x.ReadByID($*_)`, `$x.Reload($*_)`, `$x.Serialize($*_)`).Where(m["x"].Type.Is("resources.subnet")).Report(`panic danger`)
}

func VolumeDanger(m dsl.Matcher) {
	m.Import("github.com/CS-SI/SafeScale/v22/lib/backend/resources")
	m.Match(`$x.Alter($*_)`, `$x.BrowseFolder($*_)`, `$x.Deserialize($*_)`, `$x.GetService($*_)`, `$x.Inspect($*_)`, `$x.Review($*_)`, `$x.Read($*_)`, `$x.ReadByID($*_)`, `$x.Reload($*_)`, `$x.Serialize($*_)`).Where(m["x"].Type.Is("resources.volume")).Report(`panic danger`)
}

// unchecked casts, just don't

func uncheckedCast(m dsl.Matcher) {
	m.Match(`$x := $y.($z)`, `$x = $y.($z)`).Where(!m.File().Name.Matches(`.*test.go`)).
		Report(`unchecked cast to $z, when this breaks, it panics... and adding 3 lines of code to prevent a panic is always, always, worthy`)
}

func ignoredCastError(m dsl.Matcher) {
	m.Match(`$x, _ := $y.($z)`, `$x, _ = $y.($z)`).Where(!m.File().Name.Matches(`.*test.go`)).
		Report(`good luck tracking down an error here if it breaks`)
}

func intermediateCast(m dsl.Matcher) {
	m.Match(`$x := $y.($z).$w`, `$x = $y.($z).$w`).Where(!m.File().Name.Matches(`.*test.go`)).
		Report(`unchecked cast to $z, then accessing a field, it's a panic waiting to happen... and adding 3 lines of code to prevent a panic is always, always, worthy`)
}

func intermediateCastWithFunc(m dsl.Matcher) {
	m.Match(`$x := $y.($z).$w($*_)`, `$x = $y.($z).$w($*_)`).Where(!m.File().Name.Matches(`.*test.go`)).
		Report(`unchecked cast to $z, then calling a function, it's a panic waiting to happen... and adding 3 lines of code to prevent a panic is always, always, worthy`)
}

func jsonMarshalIgnored(m dsl.Matcher) {
	m.Match(`$x, _ = json.Marshal($*_)`,
		`$x, _ := json.Marshal($*_)`,
	).Where(!m.File().Name.Matches(`.*test.go`)).
		Report("json unmarshalling errors cannot be ignored, log the error or handle it, never ignore")
}

func jsonUnMarshalIgnored(m dsl.Matcher) {
	m.Match(`$x, _ = json.UnMarshal($*_)`,
		`$x, _ := json.UnMarshal($*_)`,
	).
		Report("json unmarshalling errors cannot be ignored")
}

func removeDebugCode(m dsl.Matcher) {
	m.Match(
		"logrus.Warningf($*_, $*_)",
		"logrus.Warning($*_, $x)",
		"logrus.Warningf($*_)",
		"logrus.Warning($*_)",
	).
		Report("REMOVE debug code before a release")
}

func removeMoreDebugCode(m dsl.Matcher) {
	m.Match(
		"logrus.WithContext($*_).Warningf($*_, $*_)",
		"logrus.WithContext($*_).Warning($*_, $x)",
		"logrus.WithContext($*_).Warningf($*_)",
		"logrus.WithContext($*_).Warning($*_)",
	).
		Report("REMOVE ctx debug code before a release")
}
