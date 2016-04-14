from common_analysis_base import AnalysisPlugin, FileAnalysisMixin, URLAnalysisMixin, IPAnalysisMixin, DomainAnalysisMixin
from common_helper_files import get_directory_for_filename, get_version_string_from_git, md5sum
from virus_total_apis import PrivateApi as VirustotalApi
import logging
import time
import datetime
import random
import threading

logger = logging.getLogger('CommonAnalysisVirusTotal')
logger.setLevel(logging.INFO)

system_version = get_version_string_from_git(get_directory_for_filename(__file__))

VT_FILE_ANALYZIS_PENDING = -2
VT_FILE_UNKOWN = 0
VT_FILE_REPORT_SUBMITTED = 1


class DelayedVirustotalApi():
    last_request_time = datetime.datetime(1970, 1, 1)
    lock = threading.Lock()

    def __init__(self, api_key, backoff_time):
        self.api = VirustotalApi(api_key)
        self.backoff_time = backoff_time
        random.seed()
        rand_seconds = random.randrange(3, 16)
        self.last_request_time = datetime.datetime.now() - datetime.timedelta(seconds=rand_seconds)

    def __getattr__(self, name):
        def delay_wrapper(*args, **kwargs):
            with self.lock:
                now = datetime.datetime.now()
                time_delta = now - self.last_request_time
                if time_delta.seconds >= self.backoff_time:
                    logger.info('VT_DELAY calling {} (time_delta={})'.format(name, time_delta.seconds))
                else:
                    cur_backoff_time = self.backoff_time - time_delta.seconds
                    logger.info('Called to soon, wait for {}sec'.format(cur_backoff_time))
                    time.sleep(cur_backoff_time + 1)
                    logger.info('VT_DELAY calling {}'.format(name))
                method = getattr(self.api, name)
                vt_ret_value = method(*args, **kwargs)
                self.last_request_time = datetime.datetime.now()
            return vt_ret_value
        return delay_wrapper


class CommonAnalysisVirusTotal(AnalysisPlugin, FileAnalysisMixin, URLAnalysisMixin, IPAnalysisMixin, DomainAnalysisMixin):
    def __init__(self, api_key, backoff_time=16):
        """
        CommonAnalysisVirusTotal

        :param api_key: API Key for Virustotal
        :param backoff_time: Time to sleep between requests to Virustotal in seconds.
        """
        super(CommonAnalysisVirusTotal, self).__init__(system_version)
        self.virustotal = DelayedVirustotalApi(api_key, backoff_time)

    def _send_file_to_virustotal(self, file_path):
        resp = self.virustotal.scan_file(file_path)
        if 'status_code' in resp and resp['status_code'] != 201:
            raise RuntimeError
        logger.info('{} uploaded to Virustotal.'.format(file_path))

    def _get_virustotal_file_result(self, file_path):
        with open(file_path, 'rb') as f:
            file_md5 = md5sum(f)
        vt_response = self.virustotal.get_file_report(file_md5)
        return vt_response['results']

    def wait_for_report(self, resource):
        response_code = VT_FILE_ANALYZIS_PENDING
        report = self.prepare_analysis_report_dictionary()
        if response_code == VT_FILE_UNKOWN:
            raise RuntimeError("File is unkown to Virustotal.")
        while response_code != VT_FILE_REPORT_SUBMITTED:
            logger.info('Requesting VirusTotal for result on {}'.format(resource))
            vt_response = self.virustotal.get_file_report(resource)
            if 'error' in vt_response:
                logger.error('VirustotalApi Error: {}'.format(vt_response['error']))
                continue
            result = vt_response['results']
            response_code = result['response_code']
        report['result'] = result
        return report

    def analyze_file(self, file_path, asynchronous=False):
        """
        Analyze a file.

        :param file_path: Path to the file.
        :param asynchronous: If False the method waits until Virustotal has analyzed
        the file and returns the report. If True the Virustotal resource is
        returned as handle.

        :return: Virustotal resource (md5sum) or report dict
        """
        # check if already submitted
        result = self._get_virustotal_file_result(file_path)
        if result['response_code'] != VT_FILE_REPORT_SUBMITTED:
            self._send_file_to_virustotal(file_path)

        if asynchronous:
            return result['resource']
        else:
            return self.wait_for_report(result['resource'])

    def analyze_ip(self, ip):
        report = self.prepare_analysis_report_dictionary()
        result = self.virustotal.get_ip_report(ip)['results']
        report.update(result)
        return report

    def analyze_url(self, url):
        report = self.prepare_analysis_report_dictionary()
        result = self.virustotal.get_url_report(url)['results']
        report.update(result)
        return report

    def analyze_domain(self, domain):
        report = self.prepare_analysis_report_dictionary()
        result = self.virustotal.get_domain_report(domain)['results']
        report.update(result)
        return report
