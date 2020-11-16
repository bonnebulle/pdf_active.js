/* Copyright 2020 Mozilla Foundation
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

import { initSandbox } from "../../src/scripting_api/initialization.js";

describe("Scripting", function () {
  describe("Util", function () {
    let sandbox, util;

    beforeAll(function (done) {
      sandbox = Object.create(null);
      const extra = { send: null, crackURL: null };
      const data = { objects: {}, calculationOrder: [] };
      initSandbox({ data, extra, out: sandbox });
      util = sandbox.util;
      done();
    });

    afterAll(function () {
      sandbox = util = null;
    });

    describe("printd", function () {
      it("should print a date according to a format", function (done) {
        const date = new Date("April 15, 1707 3:14:15");
        expect(util.printd(0, date)).toEqual("D:17070415031415");
        expect(util.printd(1, date)).toEqual("1707.04.15 03:14:15");
        expect(util.printd(2, date)).toEqual("4/15/07 3:14:15 am");
        expect(util.printd("mmmm mmm mm m", date)).toEqual("April Apr 04 4");
        expect(util.printd("dddd ddd dd d", date)).toEqual("Friday Fri 15 15");
        done();
      });
    });

    describe("scand", function () {
      it("should parse a date according to a format", function (done) {
        const date = new Date("April 15, 1707 3:14:15");
        expect(util.scand(0, "D:17070415031415")).toEqual(date);
        expect(util.scand(1, "1707.04.15 03:14:15")).toEqual(date);
        expect(util.scand(2, "4/15/07 3:14:15 am")).toEqual(
          new Date("April 15, 2007 3:14:15")
        );
        done();
      });
    });

    describe("printf", function () {
      it("should print some data according to a format", function (done) {
        expect(
          util.printf("Integer numbers: %d, %d,...", 1.234, 56.789)
        ).toEqual("Integer numbers: 1, 56,...");
        expect(util.printf("Hex numbers: %x, %x,...", 1234, 56789)).toEqual(
          "Hex numbers: 4D2, DDD5,..."
        );
        expect(
          util.printf("Hex numbers with 0x: %#x, %#x,...", 1234, 56789)
        ).toEqual("Hex numbers with 0x: 0x4D2, 0xDDD5,...");
        expect(util.printf("Decimal number: %,0+.3f", 1234567.89123)).toEqual(
          "Decimal number: +1,234,567.891"
        );
        expect(util.printf("Decimal number: %,0+8.3f", 1.234567)).toEqual(
          "Decimal number: +  1.235"
        );
        done();
      });

      it("should print a string with no argument", function (done) {
        expect(util.printf("hello world")).toEqual("hello world");
        done();
      });

      it("should print a string with a percent", function (done) {
        expect(util.printf("%%s")).toEqual("%%s");
        expect(util.printf("%%s", "hello")).toEqual("%%s");
        done();
      });
    });

    describe("printx", function () {
      it("should print some data according to a format", function (done) {
        expect(util.printx("9 (999) 999-9999", "aaa14159697489zzz")).toEqual(
          "1 (415) 969-7489"
        );
        done();
      });
    });
  });

  describe("Events", function () {
    let sandbox, send_queue, _app;

    beforeEach(function (done) {
      send_queue = [];
      sandbox = Object.create(null);
      const extra = {
        send(data) {
          send_queue.push(data);
        },
        crackURL: null,
      };
      const data = {
        objects: {
          field314R: [
            {
              id: "314R",
              value: "",
              actions: {},
              type: "text",
            },
          ],
          field271R: [
            {
              id: "271R",
              value: "",
              actions: {},
              type: "text",
            },
          ],
        },
        calculationOrder: ["271R"],
        dispatchEventName: "_dispatchMe",
      };

      initSandbox({
        data,
        extra,
        out: sandbox,
        testMode: true,
      });

      _app = sandbox._app;
      send_queue = [];
      done();
    });

    afterAll(function () {
      sandbox = send_queue = _app = null;
    });

    it("should trigger an event and modify the source", function (done) {
      _app._objects["314R"].obj._actions.set("test", [
        event => {
          event.source.value = "123";
        },
      ]);

      sandbox.app._dispatchMe({
        id: "314R",
        value: "",
        name: "test",
        willCommit: true,
      });

      expect(send_queue.length).toEqual(1);
      expect(send_queue[0]).toEqual({ id: "314R", value: "123" });

      done();
    });

    it("should trigger a Keystroke event and invalidate it", function (done) {
      _app._objects["314R"].obj._actions.set("Keystroke", [
        event => {
          event.rc = false;
        },
      ]);

      sandbox.app._dispatchMe({
        id: "314R",
        value: "hell",
        name: "Keystroke",
        willCommit: false,
        change: "o",
        selStart: 4,
        selEnd: 4,
      });
      expect(send_queue.length).toEqual(1);
      expect(send_queue[0]).toEqual({
        id: "314R",
        value: "hell",
        selRange: [4, 4],
      });

      done();
    });

    it("should trigger a Keystroke event and change it", function (done) {
      _app._objects["314R"].obj._actions.set("Keystroke", [
        event => {
          event.change = "a";
        },
      ]);

      sandbox.app._dispatchMe({
        id: "314R",
        value: "hell",
        name: "Keystroke",
        willCommit: false,
        change: "o",
        selStart: 4,
        selEnd: 4,
      });
      expect(send_queue.length).toEqual(1);
      expect(send_queue[0]).toEqual({ id: "314R", value: "hella" });

      done();
    });

    it("should trigger an invalid commit Keystroke event", function (done) {
      _app._objects["314R"].obj._actions.set("Validate", [
        event => {
          event.rc = false;
        },
      ]);

      sandbox.app._dispatchMe({
        id: "314R",
        value: "hello",
        name: "Keystroke",
        willCommit: true,
      });
      expect(send_queue.length).toEqual(0);

      done();
    });

    it("should trigger a valid commit Keystroke event", function (done) {
      let output = "";
      _app._objects["314R"].obj._actions.set("Validate", [
        event => {
          event.value = "world";
          output += "foo";
        },
      ]);
      _app._objects["271R"].obj._actions.set("Calculate", [
        event => {
          event.value = "hello";
          output += "bar";
        },
      ]);

      sandbox.app._dispatchMe({
        id: "314R",
        value: "hello",
        name: "Keystroke",
        willCommit: true,
      });

      expect(send_queue.length).toEqual(4);
      expect(send_queue[0]).toEqual({ id: "314R", value: "world" });
      expect(send_queue[1]).toEqual({ id: "271R", value: "hello" });
      expect(send_queue[2]).toEqual({ id: "271R", valueAsString: "hello" });
      expect(send_queue[3]).toEqual({ id: "314R", valueAsString: "world" });
      expect(output).toEqual("foobar");

      done();
    });
  });
});
