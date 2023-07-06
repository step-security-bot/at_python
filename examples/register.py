import os, sys, time

if os.path.basename(os.getcwd()) == "examples":
    base_dir = ".."
    config_path = "register.ini"
else:
    base_dir = "."
    config_path = "examples/register.ini"

sys.path.append(base_dir)
sys.path.append(f"{base_dir}/at_client/common")
sys.path.append(f"{base_dir}/at_client/connections")
sys.path.append(f"{base_dir}/at_client/util")

from configparser import ConfigParser
from argparse import ArgumentParser

import onboarding
from at_client.util import RegisterUtil, RegisterApiResult, RegisterApiTask, ApiCallStatus
from at_client.exception import AtRegistrarException

class Register:
    def __init__(self):
        self.params = {}
        self.is_registrar_v3 = False

    def main(self, args):
        parser = ArgumentParser()
        parser.add_argument("-e", "--email", help="email to register a free atsign using otp-auth")
        parser.add_argument("-k", "--api-key", help="register an atsign using super-API key")
        args = parser.parse_args(args)

        if args.email and not args.api_key:
            self.is_registrar_v3 = False
        elif not args.email and args.api_key:
            self.is_registrar_v3 = True
        else:
            parser.print_help()
            sys.exit(1)

        self.read_parameters(args.email, args.api_key)

        if self.is_registrar_v3:
            registration_flow = RegistrationFlow(self.params)
            registration_flow.add(GetAtsignV3()).add(ActivateAtsignV3()).start()
        else:
            self.params["confirmation"] = "false"
            registration_flow = RegistrationFlow(self.params)
            registration_flow.add(GetFreeAtsign()).add(RegisterAtsign()).add(ValidateOtp()).start()

        onboard_args = ["-r", self.params["rootDomain"] + ":" + self.params["rootPort"], "-a", self.params["atSign"], "-c", self.params["cram"]]
        print("Waiting 10 Seconds for server to save atsign info...")
        time.sleep(10)
        onboarding.main(onboard_args)

        return "Done."

    def read_parameters(self, email, api_key):
        try:
            config = ConfigParser()
            config.read(config_path)

            self.params["rootDomain"] = config.get("rootServer", "domain", fallback="ROOT_DOMAIN")
            self.params["rootPort"] = config.get("rootServer", "port", fallback="ROOT_PORT")
            self.params["registrarUrl"] = config.get("registrarV3" if self.is_registrar_v3 else "registrar", "url", fallback="REGISTRAR_URL")
            if not self.is_registrar_v3 and not api_key:
                self.params["apiKey"] = config.get("registrar", "apiKey", fallback="API_KEY")

            if not self.is_registrar_v3:
                self.params["email"] = email
            else:
                self.params["apiKey"] = api_key

            required_params = ["rootDomain", "rootPort", "registrarUrl", "apiKey"]
            if not all(param in self.params for param in required_params):
                print("Please make sure to set all relevant configuration in examples/register.ini")
                sys.exit(1)
        except FileNotFoundError:
            print("Config file not found.")
            sys.exit(1)


class RegistrationFlow:
    def __init__(self, params):
        self.process_flow = []
        self.result = RegisterApiResult()
        self.params = params
        self.register_util = RegisterUtil()

    def add(self, task):
        self.process_flow.append(task)
        return self

    def start(self):
        for task in self.process_flow:
            task.init(self.params, self.register_util)
            self.result = task.run()
            if self.result.api_call_status == ApiCallStatus.RETRY:
                while task.should_retry() and self.result.api_call_status == ApiCallStatus.RETRY:
                    self.result = task.run()
                    task.retry_count += 1
            if self.result.api_call_status == ApiCallStatus.SUCCESS:
                self.params.update(self.result.data)
            else:
                raise self.result.at_exception


class GetFreeAtsign(RegisterApiTask):
    def run(self):
        print("Getting free atsign ...")
        try:
            self.result.data["atSign"] = self.register_util.get_free_atsign(self.params["registrarUrl"], self.params["apiKey"])
            self.result.api_call_status = ApiCallStatus.SUCCESS
            print("Got atsign: " + self.result.data["atSign"])
        except AtRegistrarException as e:
            self.result.at_exception = e
        except Exception as e:
            print(e)
            self.result.at_exception = AtRegistrarException("error while getting free atsign")
            self.result.api_call_status = ApiCallStatus.RETRY if self.retry_count < self.max_retries else ApiCallStatus.FAILURE
        return self.result


class RegisterAtsign(RegisterApiTask):
    def run(self):
        print("Sending one-time-password to: " + self.params["email"])
        try:
            self.result.data["otpSent"] = self.register_util.register_atsign(self.params["email"], self.params["atSign"],
                                                                             self.params["registrarUrl"], self.params["apiKey"])
            self.result.api_call_status = ApiCallStatus.SUCCESS
        except Exception as e:
            self.result.at_exception = AtRegistrarException(str(e))
            self.result.api_call_status = ApiCallStatus.RETRY if self.retry_count < self.max_retries else ApiCallStatus.FAILURE
        return self.result


class ValidateOtp(RegisterApiTask):
    def run(self):
        print("Enter OTP received on " + self.params["email"] + " [note: otp is case sensitive]")
        try:
            if "otp" not in self.params:
                self.params["otp"] = input()

            print("Validating OTP ...")
            api_response = self.register_util.validate_otp(self.params["email"], self.params["atSign"],
                                                           self.params["otp"], self.params["registrarUrl"],
                                                           self.params["apiKey"], bool(self.params["confirmation"]))

            if api_response == "retry":
                print("Incorrect OTP!!! Please re-enter your OTP")
                self.params["otp"] = input()
                self.result.api_call_status = ApiCallStatus.RETRY
                self.result.at_exception = AtRegistrarException("Only 3 retries allowed to re-enter OTP - Incorrect OTP entered")
            elif api_response == "follow-up":
                self.params["confirmation"] = "true"
                self.result.api_call_status = ApiCallStatus.RETRY
            elif api_response.startswith("@"):
                self.result.data["cram"] = api_response.split(":")[1]
                print("your cram secret: " + self.result.data["cram"])
                print("Done.")
                self.result.api_call_status = ApiCallStatus.SUCCESS
        except AtRegistrarException as e:
            self.result.at_exception = e
            self.result.api_call_status = ApiCallStatus.RETRY if self.retry_count < self.max_retries else ApiCallStatus.FAILURE
        except Exception as e:
            self.result.at_exception = AtRegistrarException("Failed while validating OTP")
            self.result.api_call_status = ApiCallStatus.RETRY if self.retry_count < self.max_retries else ApiCallStatus.FAILURE
        return self.result


class GetAtsignV3(RegisterApiTask):
    def run(self):
        print("Getting atSign ...")
        try:
            self.result.data.update(self.register_util.get_atsign_v3(self.params["registrarUrl"], self.params["apiKey"]))
            print("Got atsign: " + self.result.data["atSign"])
            self.result.api_call_status = ApiCallStatus.SUCCESS
        except AtRegistrarException as e:
            self.result.at_exception = e
            self.result.api_call_status = ApiCallStatus.RETRY if self.retry_count < self.max_retries else ApiCallStatus.FAILURE
        except Exception as e:
            self.result.at_exception = AtRegistrarException("Failed while getting atSign")
            self.result.api_call_status = ApiCallStatus.RETRY if self.retry_count < self.max_retries else ApiCallStatus.FAILURE
        return self.result


class ActivateAtsignV3(RegisterApiTask):
    def run(self):
        try:
            self.result.data["cram"] = self.register_util.activate_atsign(self.params["registrarUrl"], self.params["apiKey"],
                                                                          self.params["atSign"], self.params["ActivationKey"]).split(":")[1]
            self.result.api_call_status = ApiCallStatus.SUCCESS
            print("Your cram secret: " + self.result.data["cram"])
        except AtRegistrarException as e:
            self.result.at_exception = e
            self.result.api_call_status = ApiCallStatus.RETRY if self.retry_count < self.max_retries else ApiCallStatus.FAILURE
        except Exception as e:
            self.result.at_exception = AtRegistrarException("Failed while activating atSign")
            self.result.api_call_status = ApiCallStatus.RETRY if self.retry_count < self.max_retries else ApiCallStatus.FAILURE
        return self.result
    

if __name__ == "__main__":
    register = Register()
    register.main(sys.argv[1:])