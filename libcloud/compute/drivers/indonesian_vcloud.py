# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to You under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Indonesian Cloud driver, a small wrapper around the vCloud driver

Url: http://indonesiancloud.com/

At the moment this does nothing than adding a new driver, that is
just a vCloud subclass. Could be extended in future to contain
Indonesian cloud's API url etc
"""

from libcloud.compute.types import Provider, LibcloudError
from libcloud.compute.drivers.vcloud import VCloud_1_5_Connection, VCloud_1_5_NodeDriver

IndonesianVCloud_API_URL = "compute.idcloudonline.com"


class IndonesianVCloud_1_5_Connection(VCloud_1_5_Connection):
    pass


class IndonesianVCloudNodeDriver(VCloud_1_5_NodeDriver):
    pass
