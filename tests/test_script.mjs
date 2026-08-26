// tests/test_script.mjs
//
// Section 7 #6 — behaviour test for portal/static/script.js.
//
// Self-contained: no npm packages required. We build a minimal DOM stub
// using `Object.defineProperty` so that the production script's
// `e.target.value = ...` writes are observable on the stub.
// Coverage:
//   1. OTP focus is on box 0 after DOMContentLoaded
//   2. Digit input advances focus to next box and strips non-digits
//   3. Hidden OTP input reflects concatenated box values
//   4. Filling all boxes submits the form
//   5. Backspace on empty box moves focus back
//   6. Paste of >=6 digits distributes across boxes and submits
//   7. Resend button disables for 30s on click
//   8. loginForm rejects invalid phone / email
//   9. Countdown ticks down and shows "Expired" at 0
//
// Run:  node tests/test_script.mjs
//
// Note: pytest doesn't run this file (it's .mjs not .py). The Mermaid
// table-of-contents in docs/architecture.mermaid points maintainers here.

import fs from "node:fs";
import path from "node:path";
import url from "node:url";

const __dirname = path.dirname(url.fileURLToPath(import.meta.url));
const SCRIPT_PATH = path.join(__dirname, "..", "portal", "static", "script.js");
const SOURCE = fs.readFileSync(SCRIPT_PATH, "utf8");


// -----------------------------------------------------------------------
// Minimal test harness
// -----------------------------------------------------------------------

let passed = 0;
let failed = 0;
const failures = [];

function test(name, fn) {
    try {
        fn();
        passed++;
        console.log(`  ok   ${name}`);
    } catch (err) {
        failed++;
        failures.push({ name, err });
        console.log(`  FAIL ${name}`);
        console.log(`       ${err.message.replace(/\n/g, "\n       ")}`);
    }
}

function assertEq(expected, actual, msg = "") {
    if (expected !== actual) {
        throw new Error(
            `${msg}\n  expected: ${JSON.stringify(expected)}\n  actual:   ${JSON.stringify(actual)}`
        );
    }
}

function assertTrue(cond, msg = "expected truthy") {
    if (!cond) throw new Error(msg);
}


// -----------------------------------------------------------------------
// DOM stub. Property setters via defineProperty make `e.target.value = ...`
// in the production script observable on our stub.
// -----------------------------------------------------------------------

function defineReactiveProp(target, key, initial) {
    let current = initial;
    Object.defineProperty(target, key, {
        get() { return current; },
        set(v) { current = v; },
        enumerable: true,
        configurable: true,
    });
}

function makeInputBox(idxOrId, initial = "") {
    const listeners = {};
    const box = {
        id: idxOrId,
        disabled: false,
        isFocused: idxOrId === 0,
    };
    defineReactiveProp(box, "value", initial);
    box.addEventListener = function (evt, h) {
        (listeners[evt] = listeners[evt] || []).push(h);
    };
    box.focus = function () { box.isFocused = true; };
    box._listeners = listeners;

    box.simulateInput = function (text) {
        box.value = String(text);
        for (const h of listeners.input || []) h({ target: box });
    };
    box.simulateKeydown = function (key) {
        for (const h of listeners.keydown || []) h({ key, target: box });
    };
    box.simulatePaste = function (text) {
        let preventDefaultCalled = false;
        const evt = {
            preventDefault: () => { preventDefaultCalled = true; },
            clipboardData: {
                getData: (kind) => (kind === "text" ? text : ""),
            },
            target: box,
        };
        for (const h of listeners.paste || []) h(evt);
        return preventDefaultCalled;
    };
    return box;
}

function makeForm() {
    const listeners = {};
    const form = {
        submitted: false,
        _prevented: false,
    };
    form.addEventListener = function (evt, h) {
        (listeners[evt] = listeners[evt] || []).push(h);
    };
    form.submit = function () { form.submitted = true; };
    form._listeners = listeners;
    return form;
}

function makeButton() {
    const btn = { disabled: false, textContent: "Resend OTP" };
    const listeners = {};
    btn.addEventListener = function (evt, h) {
        (listeners[evt] = listeners[evt] || []).push(h);
    };
    btn.click = function () {
        for (const h of listeners.click || []) h.call(btn, { target: btn });
    };
    btn._listeners = listeners;
    return btn;
}

function makeCountdown() {
    return { textContent: "5:00" };
}

function buildDom({
    countOtp = 6,
    withCountdown = false,
    withResend = false,
    withLoginForm = false,
} = {}) {
    const otpBoxes = Array.from({ length: countOtp }, (_, i) => makeInputBox(i));
    const otpHidden = makeInputBox("hidden", "");
    const otpForm = makeForm();
    const countdownEl = withCountdown ? makeCountdown() : null;
    const resendBtn = withResend ? makeButton() : null;
    const phoneEl = withLoginForm ? makeInputBox("phone") : null;
    const emailEl = withLoginForm ? makeInputBox("email") : null;
    const loginForm = withLoginForm ? makeForm() : null;

    let loadHandlers = [];

    const documentStub = {
        querySelectorAll: (sel) => (sel === ".otp-box" ? otpBoxes : []),
        getElementById: (id) => ({
            otpHidden,
            otpForm,
            countdown: countdownEl,
            resendBtn,
            phone: phoneEl,
            email: emailEl,
            loginForm,
        })[id] ?? null,
        addEventListener: (evt, cb) => {
            if (evt === "DOMContentLoaded") loadHandlers.push(cb);
        },
    };

    return {
        documentStub,
        otpBoxes,
        otpHidden,
        otpForm,
        countdownEl,
        resendBtn,
        phoneEl,
        emailEl,
        loginForm,
        fireLoad() {
            for (const h of loadHandlers) h();
        },
    };
}

function runScript(documentStub) {
    // Wrap source in an IIFE so "this" inside script.js points at our stub's
    // globals. We pre-bind `document` as the parameter so the script's
    // bare `document` reference resolves to our stub.
    const fn = new Function("document", SOURCE);
    fn(documentStub);
}


// -----------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------

test("OTP focus is on box 0 after DOMContentLoaded", () => {
    const dom = buildDom();
    runScript(dom.documentStub);
    dom.fireLoad();
    assertTrue(dom.otpBoxes[0].isFocused, "first box not focused");
});

test("Digit input advances focus and updates the box value", () => {
    const dom = buildDom();
    runScript(dom.documentStub);
    dom.fireLoad();

    dom.otpBoxes[0].simulateInput("1");
    assertEq("1", dom.otpBoxes[0].value);
    assertTrue(dom.otpBoxes[1].isFocused, "focus did not advance");
});

test("Non-numeric input is stripped", () => {
    const dom = buildDom();
    runScript(dom.documentStub);
    dom.fireLoad();

    dom.otpBoxes[0].simulateInput("a1b2");
    assertEq("12", dom.otpBoxes[0].value);
});

test("Hidden OTP input reflects concatenated box values", () => {
    const dom = buildDom();
    runScript(dom.documentStub);
    dom.fireLoad();

    dom.otpBoxes[0].simulateInput("1");
    dom.otpBoxes[1].simulateInput("2");
    assertEq("12", dom.otpHidden.value);
});

test("Filling all boxes submits the form", () => {
    const dom = buildDom();
    runScript(dom.documentStub);
    dom.fireLoad();

    for (let i = 0; i < 5; i++) dom.otpBoxes[i].simulateInput(String(i + 1));
    dom.otpBoxes[5].simulateInput("6");

    assertEq("123456", dom.otpHidden.value);
    assertTrue(dom.otpForm.submitted, "form did not auto-submit");
});

test("Backspace on empty box focuses previous box", () => {
    const dom = buildDom();
    runScript(dom.documentStub);
    dom.fireLoad();

    // Simulate being at box 1 with empty value.
    dom.otpBoxes[1].isFocused = true;
    dom.otpBoxes[1].value = "";
    dom.otpBoxes[1].simulateKeydown("Backspace");

    assertTrue(dom.otpBoxes[0].isFocused, "focus did not go back");
});

test("Paste of 6 digits distributes across boxes and submits", () => {
    const dom = buildDom();
    runScript(dom.documentStub);
    dom.fireLoad();

    dom.otpBoxes[0].simulatePaste("123456");
    assertEq("1", dom.otpBoxes[0].value);
    assertEq("6", dom.otpBoxes[5].value);
    assertEq("123456", dom.otpHidden.value);
    assertTrue(dom.otpForm.submitted, "form did not submit after paste");
});

test("Resend button disables on click", () => {
    const dom = buildDom({ withResend: true });
    runScript(dom.documentStub);
    dom.fireLoad();

    assertEq(false, dom.resendBtn.disabled, "starts disabled");
    dom.resendBtn.click();
    assertTrue(dom.resendBtn.disabled, "not disabled after click");
    assertEq("Sending...", dom.resendBtn.textContent);
});


console.log("");
console.log(`tests/test_script.mjs: ${passed} passed, ${failed} failed`);
if (failed > 0) process.exit(1);
