__version__ = '0.1'

from .virustotal_analysis import CommonAnalysisVirusTotal

__all__ = [
    'CommonAnalysisVirusTotal',
]

analysis_class = CommonAnalysisVirusTotal
