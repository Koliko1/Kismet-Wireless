/*
   This file is part of Kismet

   Kismet is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   Kismet is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with Kismet; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

/*
 * DEBUG: Log file handling
 * AUTHOR: CSSI (Fabrice Agagah)
 */

#include "preludetracker.h"
#include <string.h>
#include <errno.h>

#ifdef PRELUDE

Preludetracker::Preludetracker(GlobalRegistry *in_globalreg) {
	globalreg = in_globalreg;
	int ret;

	//Start client Prelude
	ret = prelude_init(0, NULL);
	if (ret < 0) {
		_MSG("Failed to init Prelude client", MSGFLAG_ERROR);
		globalreg->fatal_condition = 1;
		return;
	}

	PreludeInitClient(ANALYZER_MODEL);
}

Preludetracker::~Preludetracker() {
	prelude_deinit();
	delete client;
}

void Preludetracker::PreludeInitClient(const char *analyzer_name) {
	try {
		client = new ClientEasy(analyzer_name, 4, ANALYZER_MODEL, ANALYZER_CLASS, ANALYZER_MANUFACTURER, VERSION);
		client->start();
	} catch (PreludeError const &error) {
		_MSG("Failed to create Prelude client", MSGFLAG_ERROR);
		globalreg->fatal_condition = 1;

		return;
	}
}

int Preludetracker::RaiseHeavyAlert(int in_ref, kis_packet *in_pack,
							mac_addr bssid, mac_addr source, mac_addr dest,
							mac_addr other, int in_channel, string in_text) {

	IDMEF idmef;
	// Classification
	idmef.set("alert.classification.text", "Suspicious network detected");

	// Source
	if (!source.Mac2String().empty()) {
		idmef.set("alert.source(0).node.address(0).category", "mac");
		idmef.set("alert.source(0).node.address(0).address", source.Mac2String().c_str());
	}

	// Target
	if (!dest.Mac2String().empty()) {
		idmef.set("alert.target(0).node.address(0).category", "mac");
		idmef.set("alert.target(0).node.address(0).address", dest.Mac2String().c_str());
	}

	// Assessment
	idmef.set("alert.assessment.impact.severity", "high");
	idmef.set("alert.assessment.impact.completion", "succeeded");
	idmef.set("alert.assessment.impact.description", in_text);

	// Additional Data
	if (!bssid.Mac2String().empty()) {
		idmef.set("alert.additional_data(>>).meaning", "BSSID");
		idmef.set("alert.additional_data(-1).data", bssid.Mac2String().c_str());
	}

	if (!other.Mac2String().empty()) {
		idmef.set("alert.additional_data(>>).meaning", "Other");
		idmef.set("alert.additional_data(-1).data", other.Mac2String().c_str());
	}

	idmef.set("alert.additional_data(>>).meaning", "Channel");
	idmef.set("alert.additional_data(-1).data", in_channel);

	idmef.set("alert.additional_data(>>).meaning", "in_ref");
	idmef.set("alert.additional_data(-1).data", in_ref);

	client->sendIDMEF(idmef);

	return 0;
}

int Preludetracker::RaiseDetectNetwork(string type, string network, Netracker::tracked_network *net, kis_ieee80211_packinfo *packinfo) {

	IDMEF idmef;
	string classif = "New "+ type +" network detected";

	// Classification
	idmef.set("alert.classification.text", classif);

	// Source
	if (!packinfo->source_mac.Mac2String().empty()) {
		idmef.set("alert.source(0).node.address(0).category", "mac");
		idmef.set("alert.source(0).node.address(0).address", packinfo->source_mac.Mac2String().c_str());
	}

	// Target
	if (!packinfo->dest_mac.Mac2String().empty()) {
		idmef.set("alert.target(0).node.address(0).category", "mac");
		idmef.set("alert.target(0).node.address(0).address", packinfo->dest_mac.Mac2String().c_str());
	}

	idmef.set("alert.assessment.impact.severity", "info");
	idmef.set("alert.assessment.impact.completion", "succeeded");

	string d;

	if (net->lastssid == NULL) {
		d = '?';
		idmef.set("alert.assessment.impact.description", "A new network has been discovered.");
	} else {
		if (net->lastssid->cryptset == crypt_wep || (net->lastssid->cryptset & crypt_wpa_migmode)) {
			d = 'W';
			idmef.set("alert.assessment.impact.description", "A new network has been discovered. It has a Factory default settings in use!");
		} else if (net->lastssid->cryptset) {
			d = 'O';
			idmef.set("alert.assessment.impact.description", "A new Secure Network (WEP, WPA etc..) has been discovered.");
		} else {
			d = 'N';
			idmef.set("alert.assessment.impact.description", "A new Unciphered Network has been discovered.");
		}
	}

	// Additional Data
	if (!network.empty()) {
		idmef.set("alert.additional_data(>>).meaning", "Network Name");
		idmef.set("alert.additional_data(-1).data", network.c_str());
	}

	idmef.set("alert.additional_data(>>).meaning", "Crypset");
	idmef.set("alert.additional_data(-1).data", net->data_cryptset);

	idmef.set("alert.additional_data(>>).meaning", "One of the SSIDs decrypted ?");
	idmef.set("alert.additional_data(-1).data", net->decrypted);

	idmef.set("alert.additional_data(>>).meaning", "Network Channel");
	idmef.set("alert.additional_data(-1).data", net->channel);

	idmef.set("alert.additional_data(>>).meaning", "Data Packet");
	idmef.set("alert.additional_data(-1).data", net->data_packets);

	idmef.set("alert.additional_data(>>).meaning", "LLC Packet");
	idmef.set("alert.additional_data(-1).data", net->llc_packets);

	idmef.set("alert.additional_data(>>).meaning", "Crypt Packet");
	idmef.set("alert.additional_data(-1).data", net->crypt_packets);

	idmef.set("alert.additional_data(>>).meaning", "Amount of data seen");
	idmef.set("alert.additional_data(-1).data", net->datasize);

	if (!net->freq_mhz_map.empty()) {
		idmef.set("alert.additional_data(>>).meaning", "Last Frequency (mbits)");
		idmef.set("alert.additional_data(-1).data", (int)net->freq_mhz_map.rbegin()->second);
	}

	if (!net->manuf.empty()) {
		idmef.set("alert.additional_data(>>).meaning", "Manufacture");
		idmef.set("alert.additional_data(-1).data", net->manuf);
	}

	idmef.set("alert.additional_data(>>).meaning", "First time seen");
	idmef.set("alert.additional_data(-1).data",  ctime(&net->first_time));
	idmef.set("alert.additional_data(>>).meaning", "Last time seen");
	idmef.set("alert.additional_data(-1).data",  ctime(&net->last_time));

	idmef.set("alert.additional_data(>>).meaning", "Nb_disconnected_clients");
	idmef.set("alert.additional_data(-1).data", net->client_disconnects);

	idmef.set("alert.additional_data(>>).meaning", "Last sequence value");
	idmef.set("alert.additional_data(-1).data", net->last_sequence);

	idmef.set("alert.additional_data(>>).meaning", "Number of duplicate IV counts");
	idmef.set("alert.additional_data(-1).data", net->dupeiv_packets);

	if (!net->cdp_dev_id.empty()) {
		idmef.set("alert.additional_data(>>).meaning", "cdp_dev_id");
		idmef.set("alert.additional_data(-1).data", net->cdp_dev_id);
	}

	if (!net->cdp_port_id.empty()) {
		idmef.set("alert.additional_data(>>).meaning", "cdp_port_id");
		idmef.set("alert.additional_data(-1).data", net->cdp_port_id);
	}

	idmef.set("alert.additional_data(>>).meaning", "Fragment within the last second");
	idmef.set("alert.additional_data(-1).data", net->fragments);

	idmef.set("alert.additional_data(>>).meaning", "retries within the last second");
	idmef.set("alert.additional_data(-1).data", net->retries);

	idmef.set("alert.additional_data(>>).meaning", "Number of packets since last tick");
	idmef.set("alert.additional_data(-1).data", net->new_packets);

	idmef.set("alert.additional_data(>>).meaning", "Network is dirty");
	idmef.set("alert.additional_data(-1).data", net->dirty);

	idmef.set("alert.additional_data(>>).meaning", "Alert triggered");
	idmef.set("alert.additional_data(-1).data", net->alert);

	idmef.set("alert.additional_data(>>).meaning", "last BSS timestamp");
	idmef.set("alert.additional_data(-1).data", net->bss_timestamp);

	if (!packinfo->bssid_mac.Mac2String().empty()) {
		idmef.set("alert.additional_data(>>).meaning", "BSSID");
		idmef.set("alert.additional_data(-1).data", packinfo->bssid_mac.Mac2String().c_str());
	}

	if (!packinfo->other_mac.Mac2String().empty()) {
		idmef.set("alert.additional_data(>>).meaning", "Other");
		idmef.set("alert.additional_data(-1).data", packinfo->other_mac.Mac2String().c_str());
	}

	idmef.set("alert.additional_data(>>).meaning", "Corrupt 802.11 frame");
	idmef.set("alert.additional_data(-1).data", packinfo->corrupt);


	if (!packinfo->ssid.empty()) {
		idmef.set("alert.additional_data(>>).meaning", "Raw SSID");
		idmef.set("alert.additional_data(-1).data", packinfo->ssid);
	}

	idmef.set("alert.additional_data(>>).meaning", "Length of the SSID header field");
	idmef.set("alert.additional_data(-1).data", packinfo->ssid_len);

	idmef.set("alert.additional_data(>>).meaning", "Is The SSID empty spaces");
	idmef.set("alert.additional_data(-1).data", packinfo->ssid_blank);

	if (!packinfo->wps_device_name.empty()) {
		idmef.set("alert.additional_data(>>).meaning", "WPS Device Name");
		idmef.set("alert.additional_data(-1).data", packinfo->wps_device_name);
	}

	if (!packinfo->wps_model_name.empty()) {
		idmef.set("alert.additional_data(>>).meaning", "WPS Model Name");
		idmef.set("alert.additional_data(-1).data", packinfo->wps_model_name);
	}

	if (!packinfo->wps_model_number.empty()) {
		idmef.set("alert.additional_data(>>).meaning", "WPS Model Number");
		idmef.set("alert.additional_data(-1).data", packinfo->wps_model_number);
	}

	if (!type.empty()) {
		idmef.set("alert.additional_data(>>).meaning", "Network Type");
		idmef.set("alert.additional_data(-1).data", type);
	}

	idmef.set("alert.additional_data(>>).meaning", "Is this encrypted");
	idmef.set("alert.additional_data(-1).data", packinfo->encrypted);

	idmef.set("alert.additional_data(>>).meaning", "Crypset");
	idmef.set("alert.additional_data(-1).data", packinfo->cryptset);

	idmef.set("alert.additional_data(>>).meaning", "Packet Channel");
	idmef.set("alert.additional_data(-1).data", packinfo->channel);

	if (!packinfo->beacon_info.empty()) {
		idmef.set("alert.additional_data(>>).meaning", "Beacon Info");
		idmef.set("alert.additional_data(-1).data", packinfo->beacon_info);
	}

	idmef.set("alert.additional_data(>>).meaning", "Beacon Interval");
	idmef.set("alert.additional_data(-1).data", packinfo->beacon_interval);

	idmef.set("alert.additional_data(>>).meaning", "Beacon Rate");
	idmef.set("alert.additional_data(-1).data", packinfo->maxrate);

	idmef.set("alert.additional_data(>>).meaning", "Datasize");
	idmef.set("alert.additional_data(-1).data", packinfo->datasize);

	if (!packinfo->wps_manuf.empty()) {
		idmef.set("alert.additional_data(>>).meaning", "WPS Manufacture");
		idmef.set("alert.additional_data(-1).data", packinfo->wps_manuf);
	}

	idmef.set("alert.additional_data(>>).meaning", "Country");
	idmef.set("alert.additional_data(-1).data", packinfo->dot11d_country);

	idmef.set("alert.additional_data(>>).meaning", "LastSSID");
	idmef.set("alert.additional_data(-1).data", d );

	client->sendIDMEF(idmef);

	return 0;
}

int Preludetracker::RaiseCryptAlert(string bssid, string network) {

	IDMEF idmef;

	string describ = "Some APs look for nearby APs with the same SSID by broadcasting probe requests for their own SSID. This will cause a flood of false CRYPTODROP alerts if the AP advertises encryption in its beacons but sends these probe requests with no encryption information. So we present an appropriate message only once.";

	string info = "The BSSID "+ bssid +"(network "+ network +") appears to probe for nearby APs with the same SSID";

	string classif = "New network with the same SSID discovered";

	// Classification
	idmef.set("alert.classification.text", classif);

	// Source
	if (!bssid.empty()) {
		idmef.set("alert.source(0).node.address(0).category", "mac");
		idmef.set("alert.source(0).node.address(0).address", bssid);
	}

	idmef.set("alert.assessment.impact.severity", "low");
	idmef.set("alert.assessment.impact.completion", "succeeded");
	idmef.set("alert.assessment.impact.description", describ);

	// Additional Data
	if (!network.empty()) {
		idmef.set("alert.additional_data(>>).meaning", "Network");
		idmef.set("alert.additional_data(-1).data", network);
	}

	idmef.set("alert.additional_data(>>).meaning", "Problem");
	idmef.set("alert.additional_data(-1).data", info);

	client->sendIDMEF(idmef);

	return 0;
}
#endif
