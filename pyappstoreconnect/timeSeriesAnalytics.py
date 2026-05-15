import inspect
import json

class TimeSeriesAnalyticsMixin:
    def timeSeriesAnalytics(self, adamId, measures, startTime, endTime, frequency, group=None, dimensionFilters=list(), apiVersion='v1'):
        """
        https://github.com/fastlane/fastlane/blob/master/spaceship/lib/spaceship/tunes/tunes_client.rb#L633
        """

        defName = inspect.stack()[0][3]
        if not isinstance(adamId, list):
            adamId = [adamId]
        if not isinstance(measures, list):
            measures = [measures]

        payload = {
            "adamId": adamId,
            "measures": measures,
            "dimensionFilters": dimensionFilters,
            "startTime": startTime,
            "endTime": endTime,
            "frequency": frequency,
        }
        if group != None:
            payload['group'] = group
        headers = {
            "X-Requested-By": "appstoreconnect.apple.com",
        }
        url=f"https://appstoreconnect.apple.com/analytics/api/{apiVersion}/data/time-series"
        self.logger.debug(f"{defName}: payload={json.dumps(payload)}")
        response = self.session.post(url, json=payload, headers=headers)

        # check status_code
        if response.status_code != 200:
            self.logger.error(f"{defName}: status_code='{response.status_code}', payload='{payload}', response.text='{response.text}'")
            return False

        # check json data
        try:
            data = response.json()
        except Exception as e:
            self.logger.error(f"{defName}: failed get response.json(), error='{str(e)}'")
            return None

        # check results
        if 'results' not in data:
            self.logger.error(f"{defName}: 'results' not found in response.json()='{data}'")
            return False

        return data
