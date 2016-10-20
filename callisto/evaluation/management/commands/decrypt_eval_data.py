import json
import csv

import environ
import gnupg
import six
import pytz

from django.conf import settings
from django.core.management.base import BaseCommand

from callisto.evaluation.models import EvalRow

env = environ.Env()


class Command(BaseCommand):
    help = 'decrypts eval data. can only be run in local environments (import data from prod)'

    def handle(self, *args, **options):
        if not settings.DEBUG:
            raise RuntimeError("Don't run this in production!!! Import encrypted prod data to your local environment")
        eval_key = env('CALLISTO_EVAL_PRIVATE_KEY')
        decrypted_eval_data = []
        for row in EvalRow.objects.all():
            tzname = settings.REPORT_TIME_ZONE or 'America/Los_Angeles'
            timezone = pytz.timezone(tzname)
            decrypted_row = {'pk': row.pk,
                             'user': row.user_identifier,
                             'record': row.record_identifier,
                             'action': row.action,
                             'timestamp': row.timestamp.astimezone(timezone).strftime('%x %X')}
            gpg = gnupg.GPG()
            gpg.import_keys(eval_key)
            decrypted_eval_row = six.text_type(gpg.decrypt(six.binary_type(row.row)))
            if decrypted_eval_row:
                decrypted_row.update(json.loads(decrypted_eval_row))
            decrypted_eval_data.append(decrypted_row)
        with open('eval_data.json', 'w') as json_output:
            json.dump(decrypted_eval_data, json_output, indent=2)
        self.stdout.write("Decrypted eval data written to eval_data.json")
        with open('eval_data.csv', 'w') as csv_output:
            # field names are not optional
            field_names = ['pk', 'user', 'record', 'action', 'timestamp', 'answered', 'unanswered']
            for row in decrypted_eval_data:
                keys = list(row.keys())
                keys.sort()
                for key in keys:
                    # flatten multiple
                    if key.endswith("_multiple"):
                        mult_dict = row[key]
                        for idx, mult_row in enumerate(mult_dict):
                            mult_keys = list(mult_row.keys())
                            mult_keys.sort()
                            for mult_key in mult_keys:
                                flat_key = key.split('_multiple', 1)[0] + "_" + mult_key + "_" + str(idx)
                                row[flat_key] = mult_row[mult_key]
                                if flat_key not in field_names:
                                    field_names.append(flat_key)
                        del row[key]
                    elif key not in field_names:
                        field_names.append(key)
            writer = csv.DictWriter(csv_output, fieldnames=field_names)
            writer.writeheader()
            writer.writerows(decrypted_eval_data)
        self.stdout.write("Decrypted eval data written to eval_data.csv")
