import argparse
import json
import os
from string import Template


ROOT = os.path.dirname(os.path.abspath(__file__))


class Generator:

    _PATH = os.path.join(ROOT, 'data', 'resource-template.json')

    def __init__(self, data):
        self._data = json.loads(data)

    @classmethod
    def from_default_template(cls):
        return cls(open(cls._PATH, 'r').read())

    def generate(self, pretty=False):
        if pretty:
            data = json.dumps(self._data, indent=4)
        else:
            data = json.dumps(self._data)
        template = Template(data)
        return template.substitute()

    def configure_email_verification(self, args):
        if args.domain:
            email_option = 'CONFIRM_WITH_LINK'
            self._data['Resources']['Domain'] = {
                "Type" : "AWS::Cognito::UserPoolDomain",
                "Properties" : {
                    "Domain" : args.domain,
                    "UserPoolId" : {"Ref": "UserPool"}
                }
            }
        else:
            email_option = 'CONFIRM_WITH_CODE'
        self._data['Resources']['UserPool'][
            'Properties']['VerificationMessageTemplate'] = {
                "DefaultEmailOption": email_option,
                "EmailSubjectByLink": args.subject,
            }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '--domain',
        help=(
            'Cognito domain name prefix. This allows for sending an email '
            'with a clickable link to activate an account. The link will '
            'go to a cognito domain with this value as the prefix. These must '
            'be unique on a per-region basis. It must also be a valid domain.'
        ))
    parser.add_argument(
        '--confirm-email-subject',
        required=True,
        dest='subject',
        help=(
            'Sets the subject of the registration confirmation email.'
        )
    )
    parser.add_argument('--pretty/--no-pretty', action='store_true', default=False,
                        dest='pretty')
    args = parser.parse_args()
    gen = Generator.from_default_template()
    gen.configure_email_verification(args)
    print(gen.generate(pretty=args.pretty))


if __name__ == "__main__":
    main()
