import inspect
import json

class MetricsWithGroupMixin:
    def metricsWithGroups(self, appleId, metrics=list(), groups=list(), days=7, startTime=None, endTime=None, frequency='week'):
        """
        get metrics with grouping
        """

        defName = inspect.stack()[0][3]

        if not isinstance(metrics, list):
            metrics = [metrics]
        if not isinstance(groups, list):
            groups = [groups]

        # set default time interval
        if not startTime and not endTime:
            timeInterval = self.timeInterval(days)
            startTime = timeInterval['startTime']
            endTime = timeInterval['endTime']

        # get available options for groups
        for metric in metrics:
            # get available dimensions id for metrics {{
            self.logger.debug(f"{defName}: metric={metric}")
            try:
                measures = self.apiSettingsAll.get('measures')
            except Exception as e:
                raise Exception(f"{defName}: failed to get 'measures' from apiSettingsAll, error={str(e)}, apiSettingsAll dump: {json.dumps(self.apiSettingsAll, indent=2)}")
            for measure in measures:
                self.logger.debug(f"{defName}: measure={measure}")
                title = measure.get('title') or measure.get('titleLocKey')
                if measure.get('key') == metric or title == metric:
                    availableDimensionsIds = measure['dimensions']
                    self.logger.debug(f"{defName}: metric={metric}, available dimensions={availableDimensionsIds}")
            # }}
            for group in groups:
                dimensions = self.apiSettingsAll.get('dimensions')
                for dimension in dimensions:
                    if dimension['key'] == group:
                        if dimension['id'] in availableDimensionsIds:
                            self.logger.debug(f"{defName}: group={group}, available option dimension['title']={dimension['title']}")
                        else:
                            self.logger.debug(f"{defName}: group={group}, dimension['title']={dimension['title']}, dimension['id']={dimension['id']} not in availableDimensionsIds={availableDimensionsIds}")
                            continue
                        args = {
                            'adamId': appleId,
                            'measures': metric,
                            'frequency': frequency,
                            'startTime': startTime,
                            'endTime': endTime,
                            'group': {
                                'metric': metric,
                                'dimension': group,
                                'rank': 'DESCENDING',
                                'limit': 10,
                            }
                        }
                        response = self.timeSeriesAnalytics(**args)
                        yield {
                            'settings': args,
                            'response': response,
                        }

