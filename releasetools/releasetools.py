# Copyright (C) 2012 The Android Open Source Project
# Copyright (C) 2016 The OmniROM Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

""" Custom OTA commands for Sony devices """

import common
import re
import os

TARGET_DIR = os.getenv('OUT')
UTILITIES_DIR = os.path.join(TARGET_DIR, 'utilities')

def FullOTA_InstallEnd(info):
  info.output_zip.write(os.path.join(UTILITIES_DIR, "updater.sh"), "updater.sh")

  info.script.AppendExtra(
        ('package_extract_file("updater.sh", "/tmp/updater.sh");\n'))

  info.script.AppendExtra('run_program("/sbin/sh", "/tmp/updater.sh");')
