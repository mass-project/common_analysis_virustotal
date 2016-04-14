from common_analysis_base import AnalysisPlugin, FileAnalysisMixin, URLAnalysisMixin, IPAnalysisMixin, DomainAnalysisMixin
from common_helper_files import get_directory_for_filename, get_version_string_from_git, read_in_chunks, md5sum
from virus_total_apis import PublicApi as VirustotalPublicApi
import logging
import pprint
import asyncio
import time

logger = logging.getLogger('CommonAnalysisVirusTotal')
logger.setLevel(logging.INFO)

system_version = get_version_string_from_git(get_directory_for_filename(__file__))

VT_FILE_ANALYZIS_PENDING = -2
VT_FILE_UNKOWN = 0
VT_FILE_REPORT_SUBMITTED = 1


class CommonAnalysisVirusTotal(AnalysisPlugin, FileAnalysisMixin, URLAnalysisMixin, IPAnalysisMixin, DomainAnalysisMixin ):
    def __init__(self, api_key, sleep_time=16):
        """
        CommonAnalysisVirusTotal

        :param api_key: API Key for Virustotal 
        :param sleep_time: Time to sleep between requests to Virustotal in seconds.
        """
        super(CommonAnalysisVirusTotal, self).__init__(system_version)
        self.virustotal = VirustotalPublicApi(api_key)

    def _send_file_to_virustotal(self,file_path):
        self.virustotal.scan_file(file_path)
        logger.info('{} uploaded to Virustotal.'.format(file_path))

    def _get_virustotal_file_result(self,file_path):
        with open(file_path, 'rb') as f:
            file_md5 = md5sum(f)
        return self.virustotal.get_file_report(file_md5)['results']

    def wait_for_report(self, resource):
        response_code = VT_FILE_ANALYZIS_PENDING
        report = self.prepare_analysis_report_dictionary()
        while response_code != VT_FILE_REPORT_SUBMITTED:
            time.sleep(self.sleep_time)
            logger.info('Requesting VirusTotal for result on {}'.format(resource))
            result = self.virustotal.get_file_report(resource)['results']
            response_code = result['response_code']
        report['result'] = result
        return report

    def analyze_file(self, file_path, async=False):
        """
        Analyze a file.

        :param file_path: Path to the file.
        :param async: If False the method waits until Virustotal has analyzed
        the file and returns the report. If True the Virustotal resource is
        returned as handle.

        :return: Virustotal resource (md5sum) or report dict
        """
        # check if already submitted
        result = self._get_virustotal_file_result(file_path)
        if result['response_code'] != VT_FILE_REPORT_SUBMITTED:
            self._send_file_to_virustotal(file_path)

        if async:
            return result['resource']
        else:
            return wait_for_report(result['resource'])

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

