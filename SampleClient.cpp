/*
Copyright © 2012 NaturalPoint Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License. */


/*

SampleClient.cpp

This program connects to a NatNet server, receives a data stream, and writes that data stream
to an ascii file.  The purpose is to illustrate using the NatNetClient class.

Usage [optional]:

	SampleClient [ServerIP] [LocalIP] [OutputFilename]

	[ServerIP]			IP address of the server (e.g. 192.168.0.107) ( defaults to local machine)
	[OutputFilename]	Name of points file (pts) to write out.  defaults to Client-output.pts

*/


#ifdef _WIN32
#   include <conio.h>
#else
#   include <unistd.h>
#   include <termios.h>
#endif

#include <NatNetTypes.h>
#include <NatNetCAPI.h>
#include <NatNetClient.h>

// start out by enabling ALL features for now.
#define CORELINK_ENABLE_ALL_FEATURES
// include corelink stuff
#include "corelink_all.hpp"


#define print_delim std::cout << "-------------------------------------------\n"

// we use this condition variable to communicate between the app and the main thread.
std::condition_variable con_var;
// the mutex is purely used for condition variable locking
std::mutex con_var_mtx;


class CorelinkConnector
{
private:
	const char* STAY_AWAKE_STR = "  ";
	bool break_keep_awake_thread = false;

public:
	corelink::client::corelink_classic_client corelink_client;
	corelink::client::corelink_client_connection_info control_channel_connect_info;
	corelink::core::network::channel_id_type control_channel_id{};
	corelink::core::network::channel_id_type sender_data_channel{};

	explicit CorelinkConnector(
		corelink::in<corelink::core::network::constants::protocols::protocol> control_ch_proto,
		corelink::in<std::string> client_cert_path = "",
		corelink::in<std::string> endpoint = "corelink.hsrn.nyu.edu",
		corelink::in<uint16_t> control_port_number = 20012) :
		control_channel_connect_info(control_ch_proto)
	{
		// this is where I would ideally start setting up objects for the corelink client.

		// first prepare the connection info instance. this will then be passed in to the client to be consumed
		// to connect and authenticate with the server
		control_channel_connect_info
			.set_port_number(control_port_number)
			.set_endpoint(endpoint)
			.set_username(corelink::client::corelink_client_connection_info::DEFAULT_USERNAME)
			.set_password(corelink::client::corelink_client_connection_info::DEFAULT_PASSWORD)
			.set_certificate_path(client_cert_path);
	}

	void on_control_channel_error(
		corelink::core::network::channel_id_type channel_id,
		corelink::in<std::string> message)
	{
		std::cout << "An error was reported on the control channel id: " << channel_id << "\n";
		std::cout << message << "\n";
		print_delim;
	}

	void keep_awake()
	{
		while (!break_keep_awake_thread) {
			corelink_client.send_data(
				sender_data_channel
				, std::vector<uint8_t>(STAY_AWAKE_STR, STAY_AWAKE_STR + std::strlen(STAY_AWAKE_STR))
				, corelink::utils::json()
			);
			std::cout << "Sending out a stay alive packet\n";
			std::this_thread::sleep_for(std::chrono::seconds(20));
		}
	}

	void auth_response_handler(corelink::core::network::channel_id_type channel_id,
		corelink::in<std::string> /*msg*/,
		corelink::in<std::shared_ptr<corelink::client::request_response::responses::corelink_server_response_base>> response
	)
	{
		if (response->status_code != 0)
		{
			std::cout << "Auth failed on channel with ID: " << channel_id << ". Message obtained: " << response->message
				<< "\n";
			print_delim;
			return;
		}
		std::cout << "Auth is okay. we are now free to use the client\n";

		auto request =
			std::make_shared<corelink::client::request_response::requests::modify_sender_stream_request>(
				corelink::core::network::constants::protocols::udp);
		request->alert = true;
		request->echo = true;
		request->workspace = "Chalktalk";
		request->stream_type = "bones";
		request->meta = "Some information describing the stream";

		request->on_error = [](corelink::core::network::channel_id_type /*host_id*/, corelink::in<std::string> err)
		{
			std::cerr << "Error while sending data on the data channel: " << err << "\n";
			print_delim;
		};
		request->on_send = [](corelink::core::network::channel_id_type host_id, size_t bytes_sent)
		{
			//std::cout << "Sent out [" << bytes_sent << "] bytes on channel id" << host_id << "\n";
			//print_delim;
		};
		request->on_init = [&](corelink::core::network::channel_id_type host_id)
		{
			sender_data_channel = host_id;
			std::thread keepAliveThread(&CorelinkConnector::keep_awake, this);
			keepAliveThread.detach();
			con_var.notify_one();
		};

		corelink_client.request(
			control_channel_id,
			corelink::client::corelink_functions::create_sender,
			request,
			[](corelink::core::network::channel_id_type /*channel_id*/,
				corelink::in<std::string> /*msg*/,
				corelink::in<std::shared_ptr<corelink::client::request_response::responses::corelink_server_response_base>> response)
			{
				std::cout << "Created sender stream!\n";
			}
		);
	}

	void add_on_update_handler()
	{
		corelink_client.request(
			control_channel_id,
			corelink::client::corelink_functions::server_callback_on_update,
			nullptr,
			[](
				corelink::core::network::channel_id_type host_id,
				corelink::in<std::string> msg,
				corelink::in<std::shared_ptr<corelink::client::request_response::responses::corelink_server_response_base>> response)
			{
				if (response)
				{
					auto server_response =
						std::static_pointer_cast<corelink::client::request_response::responses::server_cb_on_update_response>(
							response);
					std::cout << "Someone published to the stream type " << server_response->type << "\n";
					print_delim;
				}
				else
				{
					std::cout << "Something went wrong when the server tried to tell us that someone started pushing data we were interested in. Msg: " << msg << "\n";
				}
			}
		);
	}

	void add_on_subscribed_handler()
	{
		corelink_client.
			request(
				control_channel_id,
				corelink::client::corelink_functions::server_callback_on_subscribed,
				nullptr,
				[&](corelink::core::network::channel_id_type /*host_id*/,
					corelink::in<std::string> msg,
					corelink::in<std::shared_ptr<corelink::client::request_response::responses::corelink_server_response_base>> response)
				{
					if (response)
					{
						auto server_response =
							std::static_pointer_cast<corelink::client::request_response::responses::server_cb_on_subscribed_response>(
								response);
						std::cout << "Receiver stream " << server_response->receiver_id << " subscribed to the stream based on the type we are publshing\n";
						print_delim;
					}
					else
					{
						std::cout << "Something went wrong when the server tried to tell us that someone started reading data that we are publishing. Msg: " << msg << "\n";
					}
				}
		);
	}

	void on_control_channel_connection_init(corelink::core::network::channel_id_type channel_id)
	{
		std::cout << "Control channel with ID " << channel_id << " was connected. Proceeding with authentication\n";
		print_delim;

		// we now authenticate using the username and the password we have
		// we use the request function for this for the control channel we are interested in
		// and provide a response handler
		corelink_client.request(
			control_channel_id,
			corelink::client::corelink_functions::authenticate,
			std::make_shared<corelink::client::request_response::requests::authenticate_client_request>(
				control_channel_connect_info.username,
				control_channel_connect_info.password),
			std::bind(&CorelinkConnector::auth_response_handler,
				this,
				std::placeholders::_1,
				std::placeholders::_2,
				std::placeholders::_3)
		);
	}

	void on_control_channel_connection_uninit(corelink::core::network::channel_id_type channel_id)
	{
		std::cout << "Control channel connection with ID " << channel_id << " was disconnected.\n";
		print_delim;
	}

	void init()
	{
		// we start initializing the dynamic parts of corelink here.
		if (!corelink_client.init_protocols())
		{
			throw std::runtime_error(
				"Failed to initialize protocol information. Please contact corelink development");
		}

		// now that protocols are initialized, we can proceed with creating a control channel with the server
		control_channel_id = corelink_client.add_control_channel(
			control_channel_connect_info,
			std::bind(&CorelinkConnector::on_control_channel_error, this, std::placeholders::_1, std::placeholders::_2),
			std::bind(&CorelinkConnector::on_control_channel_connection_init, this, std::placeholders::_1),
			std::bind(&CorelinkConnector::on_control_channel_connection_uninit, this, std::placeholders::_1)
		);

		add_on_subscribed_handler();
		add_on_update_handler();
	}

	void teardown()
	{
		break_keep_awake_thread = true;
		corelink_client.request(
			control_channel_id,
			corelink::client::corelink_functions::disconnect,
			std::make_shared<corelink::client::request_response::requests::disconnect_streams_request>(),
			[](corelink::core::network::channel_id_type channel_id,
				corelink::in<std::string> /*msg*/,
				corelink::in<std::shared_ptr<corelink::client::request_response::responses::corelink_server_response_base>> response)
			{
				if (response->status_code == 0)
				{
					std::cout << "Channel session with ID " << channel_id << " was purged\n";
					print_delim;
				}
		con_var.notify_one();
			}
		);
	}

	~CorelinkConnector()
	{
	}
};

inline void waitForSignal()
{
	std::unique_lock<std::mutex> lock(con_var_mtx);
	con_var.wait(
		lock
	);
}

//#define USE_JSON_FORMAT

#ifndef _WIN32
char getch();
#endif
void _WriteHeader(FILE* fp, sDataDescriptions* pBodyDefs);
void _WriteFrame(FILE* fp, sFrameOfMocapData* data);
void _WriteFooter(FILE* fp);
void NATNET_CALLCONV ServerDiscoveredCallback(const sNatNetDiscoveredServer* pDiscoveredServer, void* pUserContext);
void NATNET_CALLCONV DataHandler(sFrameOfMocapData* data, void* pUserData);    // receives data from the server
void NATNET_CALLCONV MessageHandler(Verbosity msgType, const char* msg);      // receives NatNet error messages
void resetClient();
int ConnectClient();

static const ConnectionType kDefaultConnectionType = ConnectionType_Multicast;

NatNetClient* g_pClient = NULL;
FILE* g_outputFile;

std::vector< sNatNetDiscoveredServer > g_discoveredServers;
sNatNetClientConnectParams g_connectParams;
char g_discoveredMulticastGroupAddr[kNatNetIpv4AddrStrLenMax] = NATNET_DEFAULT_MULTICAST_ADDRESS;
int g_analogSamplesPerMocapFrame = 0;
sServerDescription g_serverDescription;

CorelinkConnector corelinkConnector(corelink::core::network::constants::protocols::websocket);


int main(int argc, char* argv[])
{
	// init corelink client
	corelinkConnector.init();
	waitForSignal();

	// corelink client is ready to use beyond this point

	// print version info
	unsigned char ver[4];
	NatNet_GetVersion(ver);
	printf("NatNet Sample Client (NatNet ver. %d.%d.%d.%d)\n", ver[0], ver[1], ver[2], ver[3]);

	// Install logging callback
	NatNet_SetLogCallback(MessageHandler);

	// create NatNet client
	g_pClient = new NatNetClient();

	// set the frame callback handler
	g_pClient->SetFrameReceivedCallback(DataHandler, g_pClient);	// this function will receive data from the server

	// If no arguments were specified on the command line,
	// attempt to discover servers on the local network.
	if (argc == 1)
	{
		// An example of synchronous server discovery.
#if 0
		const unsigned int kDiscoveryWaitTimeMillisec = 5 * 1000; // Wait 5 seconds for responses.
		const int kMaxDescriptions = 10; // Get info for, at most, the first 10 servers to respond.
		sNatNetDiscoveredServer servers[kMaxDescriptions];
		int actualNumDescriptions = kMaxDescriptions;
		NatNet_BroadcastServerDiscovery(servers, &actualNumDescriptions);

		if (actualNumDescriptions < kMaxDescriptions)
		{
			// If this happens, more servers responded than the array was able to store.
		}
#endif

		// Do asynchronous server discovery.
		printf("Looking for servers on the local network.\n");
		printf("Press the number key that corresponds to any discovered server to connect to that server.\n");
		printf("Press Q at any time to quit.\n\n");

		NatNetDiscoveryHandle discovery;
		NatNet_CreateAsyncServerDiscovery(&discovery, ServerDiscoveredCallback);

		while (const int c = getch())
		{
			if (c >= '1' && c <= '9')
			{
				const size_t serverIndex = c - '1';
				if (serverIndex < g_discoveredServers.size())
				{
					const sNatNetDiscoveredServer& discoveredServer = g_discoveredServers[serverIndex];

					if (discoveredServer.serverDescription.bConnectionInfoValid)
					{
						// Build the connection parameters.
#ifdef _WIN32
						_snprintf_s(
#else
						snprintf(
#endif
							g_discoveredMulticastGroupAddr, sizeof g_discoveredMulticastGroupAddr,
							"%" PRIu8 ".%" PRIu8".%" PRIu8".%" PRIu8"",
							discoveredServer.serverDescription.ConnectionMulticastAddress[0],
							discoveredServer.serverDescription.ConnectionMulticastAddress[1],
							discoveredServer.serverDescription.ConnectionMulticastAddress[2],
							discoveredServer.serverDescription.ConnectionMulticastAddress[3]
						);

						g_connectParams.connectionType = discoveredServer.serverDescription.ConnectionMulticast ? ConnectionType_Multicast : ConnectionType_Unicast;
						g_connectParams.serverCommandPort = discoveredServer.serverCommandPort;
						g_connectParams.serverDataPort = discoveredServer.serverDescription.ConnectionDataPort;
						g_connectParams.serverAddress = discoveredServer.serverAddress;
						g_connectParams.localAddress = discoveredServer.localAddress;
						g_connectParams.multicastAddress = g_discoveredMulticastGroupAddr;
					}
					else
					{
						// We're missing some info because it's a legacy server.
						// Guess the defaults and make a best effort attempt to connect.
						g_connectParams.connectionType = kDefaultConnectionType;
						g_connectParams.serverCommandPort = discoveredServer.serverCommandPort;
						g_connectParams.serverDataPort = 0;
						g_connectParams.serverAddress = discoveredServer.serverAddress;
						g_connectParams.localAddress = discoveredServer.localAddress;
						g_connectParams.multicastAddress = NULL;
					}

					break;
				}
			}
			else if (c == 'q')
			{
				return 0;
			}
		}

		NatNet_FreeAsyncServerDiscovery(discovery);
	}
	else
	{
		g_connectParams.connectionType = kDefaultConnectionType;

		if (argc >= 2)
		{
			g_connectParams.serverAddress = argv[1];
		}

		if (argc >= 3)
		{
			g_connectParams.localAddress = argv[2];
		}
	}

	int iResult;

	// Connect to Motive
	iResult = ConnectClient();
	if (iResult != ErrorCode_OK)
	{
		printf("Error initializing client. See log for details. Exiting.\n");
		return 1;
	}
	else
	{
		printf("Client initialized and ready.\n");
	}


	// Send/receive test request
	void* response;
	int nBytes;
	printf("[SampleClient] Sending Test Request\n");
	iResult = g_pClient->SendMessageAndWait("TestRequest", &response, &nBytes);
	if (iResult == ErrorCode_OK)
	{
		printf("[SampleClient] Received: %s\n", (char*)response);
	}

	// Retrieve Data Descriptions from Motive
	printf("\n\n[SampleClient] Requesting Data Descriptions...\n");
	sDataDescriptions* pDataDefs = NULL;
	iResult = g_pClient->GetDataDescriptionList(&pDataDefs);
	if (iResult != ErrorCode_OK || pDataDefs == NULL)
	{
		printf("[SampleClient] Unable to retrieve Data Descriptions.\n");
	}
	else
	{
		printf("[SampleClient] Received %d Data Descriptions:\n", pDataDefs->nDataDescriptions);
		for (int i = 0; i < pDataDefs->nDataDescriptions; i++)
		{
			printf("Data Description # %d (type=%d)\n", i, pDataDefs->arrDataDescriptions[i].type);
			if (pDataDefs->arrDataDescriptions[i].type == Descriptor_MarkerSet)
			{
				// MarkerSet
				sMarkerSetDescription* pMS = pDataDefs->arrDataDescriptions[i].Data.MarkerSetDescription;
				printf("MarkerSet Name : %s\n", pMS->szName);
				for (int i = 0; i < pMS->nMarkers; i++)
					printf("%s\n", pMS->szMarkerNames[i]);

			}
			else if (pDataDefs->arrDataDescriptions[i].type == Descriptor_RigidBody)
			{
				// RigidBody
				sRigidBodyDescription* pRB = pDataDefs->arrDataDescriptions[i].Data.RigidBodyDescription;
				printf("RigidBody Name : %s\n", pRB->szName);
				printf("RigidBody ID : %d\n", pRB->ID);
				printf("RigidBody Parent ID : %d\n", pRB->parentID);
				printf("Parent Offset : %3.2f,%3.2f,%3.2f\n", pRB->offsetx, pRB->offsety, pRB->offsetz);

				if (pRB->MarkerPositions != NULL && pRB->MarkerRequiredLabels != NULL)
				{
					for (int markerIdx = 0; markerIdx < pRB->nMarkers; ++markerIdx)
					{
						const MarkerData& markerPosition = pRB->MarkerPositions[markerIdx];
						const int markerRequiredLabel = pRB->MarkerRequiredLabels[markerIdx];

						printf("\tMarker #%d:\n", markerIdx);
						printf("\t\tPosition: %.2f, %.2f, %.2f\n", markerPosition[0], markerPosition[1], markerPosition[2]);

						if (markerRequiredLabel != 0)
						{
							printf("\t\tRequired active label: %d\n", markerRequiredLabel);
						}
					}
				}
			}
			else if (pDataDefs->arrDataDescriptions[i].type == Descriptor_Skeleton)
			{
				// Skeleton
				sSkeletonDescription* pSK = pDataDefs->arrDataDescriptions[i].Data.SkeletonDescription;
				printf("Skeleton Name : %s\n", pSK->szName);
				printf("Skeleton ID : %d\n", pSK->skeletonID);
				printf("RigidBody (Bone) Count : %d\n", pSK->nRigidBodies);
				for (int j = 0; j < pSK->nRigidBodies; j++)
				{
					sRigidBodyDescription* pRB = &pSK->RigidBodies[j];
					printf("  RigidBody Name : %s\n", pRB->szName);
					printf("  RigidBody ID : %d\n", pRB->ID);
					printf("  RigidBody Parent ID : %d\n", pRB->parentID);
					printf("  Parent Offset : %3.2f,%3.2f,%3.2f\n", pRB->offsetx, pRB->offsety, pRB->offsetz);

				}
			}
			else if (pDataDefs->arrDataDescriptions[i].type == Descriptor_ForcePlate)
			{
				// Force Plate
				sForcePlateDescription* pFP = pDataDefs->arrDataDescriptions[i].Data.ForcePlateDescription;
				printf("Force Plate ID : %d\n", pFP->ID);
				printf("Force Plate Serial : %s\n", pFP->strSerialNo);
				printf("Force Plate Width : %3.2f\n", pFP->fWidth);
				printf("Force Plate Length : %3.2f\n", pFP->fLength);
				printf("Force Plate Electrical Center Offset (%3.3f, %3.3f, %3.3f)\n", pFP->fOriginX, pFP->fOriginY, pFP->fOriginZ);
				for (int iCorner = 0; iCorner < 4; iCorner++)
					printf("Force Plate Corner %d : (%3.4f, %3.4f, %3.4f)\n", iCorner, pFP->fCorners[iCorner][0], pFP->fCorners[iCorner][1], pFP->fCorners[iCorner][2]);
				printf("Force Plate Type : %d\n", pFP->iPlateType);
				printf("Force Plate Data Type : %d\n", pFP->iChannelDataType);
				printf("Force Plate Channel Count : %d\n", pFP->nChannels);
				for (int iChannel = 0; iChannel < pFP->nChannels; iChannel++)
					printf("\tChannel %d : %s\n", iChannel, pFP->szChannelNames[iChannel]);
			}
			else if (pDataDefs->arrDataDescriptions[i].type == Descriptor_Device)
			{
				// Peripheral Device
				sDeviceDescription* pDevice = pDataDefs->arrDataDescriptions[i].Data.DeviceDescription;
				printf("Device Name : %s\n", pDevice->strName);
				printf("Device Serial : %s\n", pDevice->strSerialNo);
				printf("Device ID : %d\n", pDevice->ID);
				printf("Device Channel Count : %d\n", pDevice->nChannels);
				for (int iChannel = 0; iChannel < pDevice->nChannels; iChannel++)
					printf("\tChannel %d : %s\n", iChannel, pDevice->szChannelNames[iChannel]);
			}
			else if (pDataDefs->arrDataDescriptions[i].type == Descriptor_Camera)
			{
				// Camera
				sCameraDescription* pCamera = pDataDefs->arrDataDescriptions[i].Data.CameraDescription;
				printf("Camera Name : %s\n", pCamera->strName);
				printf("Camera Position (%3.2f, %3.2f, %3.2f)\n", pCamera->x, pCamera->y, pCamera->z);
				printf("Camera Orientation (%3.2f, %3.2f, %3.2f, %3.2f)\n", pCamera->qx, pCamera->qy, pCamera->qz, pCamera->qw);
			}
			else
			{
				printf("Unknown data type.\n");
				// Unknown
			}
		}
	}


	// Create data file for writing received stream into
	const char* szFile = "Client-output.pts";
	if (argc > 3)
		szFile = argv[3];

	g_outputFile = fopen(szFile, "w");
	if (!g_outputFile)
	{
		printf("Error opening output file %s.  Exiting.\n", szFile);
		exit(1);
	}

	if (pDataDefs)
	{
		_WriteHeader(g_outputFile, pDataDefs);
		NatNet_FreeDescriptions(pDataDefs);
		pDataDefs = NULL;
	}

	// Ready to receive marker stream!
	printf("\nClient is connected to server and listening for data...\n");
	bool bExit = false;
	while (const int c = getch())
	{
		switch (c)
		{
		case 'q':
			bExit = true;
			break;
		case 'r':
			resetClient();
			break;
		case 'p':
			sServerDescription ServerDescription;
			memset(&ServerDescription, 0, sizeof(ServerDescription));
			g_pClient->GetServerDescription(&ServerDescription);
			if (!ServerDescription.HostPresent)
			{
				printf("Unable to connect to server. Host not present. Exiting.");
				return 1;
			}
			break;
		case 's':
		{
			printf("\n\n[SampleClient] Requesting Data Descriptions...");
			sDataDescriptions* pDataDefs = NULL;
			iResult = g_pClient->GetDataDescriptionList(&pDataDefs);
			if (iResult != ErrorCode_OK || pDataDefs == NULL)
			{
				printf("[SampleClient] Unable to retrieve Data Descriptions.");
			}
			else
			{
				printf("[SampleClient] Received %d Data Descriptions:\n", pDataDefs->nDataDescriptions);
			}
		}
		break;
		case 'm':	                        // change to multicast
			g_connectParams.connectionType = ConnectionType_Multicast;
			iResult = ConnectClient();
			if (iResult == ErrorCode_OK)
				printf("Client connection type changed to Multicast.\n\n");
			else
				printf("Error changing client connection type to Multicast.\n\n");
			break;
		case 'u':	                        // change to unicast
			g_connectParams.connectionType = ConnectionType_Unicast;
			iResult = ConnectClient();
			if (iResult == ErrorCode_OK)
				printf("Client connection type changed to Unicast.\n\n");
			else
				printf("Error changing client connection type to Unicast.\n\n");
			break;
		case 'c':                          // connect
			iResult = ConnectClient();
			break;
		case 'd':                          // disconnect
			// note: applies to unicast connections only - indicates to Motive to stop sending packets to that client endpoint
			iResult = g_pClient->SendMessageAndWait("Disconnect", &response, &nBytes);
			if (iResult == ErrorCode_OK)
				printf("[SampleClient] Disconnected");
			break;
		default:
			break;
		}
		if (bExit)
			break;
	}

	// Done - clean up.
	if (g_pClient)
	{
		g_pClient->Disconnect();
		delete g_pClient;
		g_pClient = NULL;
	}

	if (g_outputFile)
	{
		_WriteFooter(g_outputFile);
		fclose(g_outputFile);
		g_outputFile = NULL;
	}

	// before we exit, we disconnect corelink streams
	corelinkConnector.teardown();
	waitForSignal();

	return ErrorCode_OK;
}


void NATNET_CALLCONV ServerDiscoveredCallback(const sNatNetDiscoveredServer* pDiscoveredServer, void* pUserContext)
{
	char serverHotkey = '.';
	if (g_discoveredServers.size() < 9)
	{
		serverHotkey = static_cast<char>('1' + g_discoveredServers.size());
	}

	printf("[%c] %s %d.%d at %s ",
		serverHotkey,
		pDiscoveredServer->serverDescription.szHostApp,
		pDiscoveredServer->serverDescription.HostAppVersion[0],
		pDiscoveredServer->serverDescription.HostAppVersion[1],
		pDiscoveredServer->serverAddress);

	if (pDiscoveredServer->serverDescription.bConnectionInfoValid)
	{
		printf("(%s)\n", pDiscoveredServer->serverDescription.ConnectionMulticast ? "multicast" : "unicast");
	}
	else
	{
		printf("(WARNING: Legacy server, could not autodetect settings. Auto-connect may not work reliably.)\n");
	}

	g_discoveredServers.push_back(*pDiscoveredServer);
}

// Establish a NatNet Client connection
int ConnectClient()
{
	// Release previous server
	g_pClient->Disconnect();

	// Init Client and connect to NatNet server
	int retCode = g_pClient->Connect(g_connectParams);
	if (retCode != ErrorCode_OK)
	{
		printf("Unable to connect to server.  Error code: %d. Exiting.\n", retCode);
		return ErrorCode_Internal;
	}
	else
	{
		// connection succeeded

		void* pResult;
		int nBytes = 0;
		ErrorCode ret = ErrorCode_OK;

		// print server info
		memset(&g_serverDescription, 0, sizeof(g_serverDescription));
		ret = g_pClient->GetServerDescription(&g_serverDescription);
		if (ret != ErrorCode_OK || !g_serverDescription.HostPresent)
		{
			printf("Unable to connect to server. Host not present. Exiting.\n");
			return 1;
		}
		printf("\n[SampleClient] Server application info:\n");
		printf("Application: %s (ver. %d.%d.%d.%d)\n", g_serverDescription.szHostApp, g_serverDescription.HostAppVersion[0],
			g_serverDescription.HostAppVersion[1], g_serverDescription.HostAppVersion[2], g_serverDescription.HostAppVersion[3]);
		printf("NatNet Version: %d.%d.%d.%d\n", g_serverDescription.NatNetVersion[0], g_serverDescription.NatNetVersion[1],
			g_serverDescription.NatNetVersion[2], g_serverDescription.NatNetVersion[3]);
		printf("Client IP:%s\n", g_connectParams.localAddress);
		printf("Server IP:%s\n", g_connectParams.serverAddress);
		printf("Server Name:%s\n", g_serverDescription.szHostComputerName);

		// get mocap frame rate
		ret = g_pClient->SendMessageAndWait("FrameRate", &pResult, &nBytes);
		if (ret == ErrorCode_OK)
		{
			float fRate = *((float*)pResult);
			printf("Mocap Framerate : %3.2f\n", fRate);
		}
		else
			printf("Error getting frame rate.\n");

		// get # of analog samples per mocap frame of data
		ret = g_pClient->SendMessageAndWait("AnalogSamplesPerMocapFrame", &pResult, &nBytes);
		if (ret == ErrorCode_OK)
		{
			g_analogSamplesPerMocapFrame = *((int*)pResult);
			printf("Analog Samples Per Mocap Frame : %d\n", g_analogSamplesPerMocapFrame);
		}
		else
			printf("Error getting Analog frame rate.\n");
	}

	return ErrorCode_OK;
}

// DataHandler receives data from the server
// This function is called by NatNet when a frame of mocap data is available 
void NATNET_CALLCONV DataHandler(sFrameOfMocapData* data, void* pUserData)
{
#if defined(USE_JSON_FORMAT)
	corelink::utils::json markerData{ false };
#else
	std::string markerDataString = "";
#endif

	//for (int i = 0; i < data->nLabeledMarkers; i++)
	//{
		//sMarker marker = data->LabeledMarkers[i];

		// Marker ID Scheme:
		// Active Markers:
		//   ID = ActiveID, correlates to RB ActiveLabels list
		// Passive Markers: 
		//   If Asset with Legacy Labels
		//      AssetID 	(Hi Word)
		//      MemberID	(Lo Word)
		//   Else
		//      PointCloud ID
		//int modelID, markerID;
		//NatNet_DecodeID(marker.ID, &modelID, &markerID);

	for (int i = 0; i < data->nSkeletons; i++)
	{
		sSkeletonData skData = data->Skeletons[i];
		for (int j = 0; j < skData.nRigidBodies; j++) {
			sRigidBodyData rbData = skData.RigidBodyData[j];

			markerDataString
				.append(std::to_string(rbData.x))
				.append(" ")
				.append(std::to_string(rbData.y))
				.append(" ")
				.append(std::to_string(rbData.z))
				.append(" ");
		}



#if defined(USE_JSON_FORMAT)
		std::vector<float> vec{
			marker.x,
			marker.y,
			marker.z
		};
		if (markerData().HasMember(std::to_string(markerID).c_str()))
		{
			markerData.append(std::to_string(markerID+40), vec);
		}
		markerData.append(std::to_string(markerID), vec);
		//std::cout << std::to_string(markerID) << "\n";
		for (size_t marker_idx = 1; marker_idx <= 81; ++marker_idx)
		{
			if (!markerData().HasMember(std::to_string(marker_idx).c_str()))
			{
				std::vector<float> vec{ 0,0,0 };
				markerData.append(std::to_string(marker_idx), vec);
			}
		}

		std::cout << markerData.to_string(true) << "\n";
		
//#else
		//markerDataString
			//.append(std::to_string(marker.x))
			//.append(" ")
			//.append(std::to_string(marker.y))
			//.append(" ")
			//.append(std::to_string(marker.z))
			//.append(" ");

		std::cout << markerDataString << "\n";
#endif
		std::cout << markerDataString << "\n";
	}


#if defined(USE_JSON_FORMAT)
	std::string markerDataString = markerData.to_string();
#endif
	if (!markerDataString.empty())
	{
		corelinkConnector.corelink_client.send_data(
			corelinkConnector.sender_data_channel,
			std::vector<uint8_t>(markerDataString.begin(), markerDataString.end()),
			corelink::utils::json()
		);
	}
}


// MessageHandler receives NatNet error/debug messages
void NATNET_CALLCONV MessageHandler(Verbosity msgType, const char* msg)
{
	// Optional: Filter out debug messages
	if (msgType < Verbosity_Info)
	{
		return;
	}

	printf("\n[NatNetLib]");

	switch (msgType)
	{
	case Verbosity_Debug:
		printf(" [DEBUG]");
		break;
	case Verbosity_Info:
		printf("  [INFO]");
		break;
	case Verbosity_Warning:
		printf("  [WARN]");
		break;
	case Verbosity_Error:
		printf(" [ERROR]");
		break;
	default:
		printf(" [?????]");
		break;
	}

	printf(": %s\n", msg);
}


/* File writing routines */
void _WriteHeader(FILE* fp, sDataDescriptions* pBodyDefs)
{
	int i = 0;

	if (pBodyDefs->arrDataDescriptions[0].type != Descriptor_MarkerSet)
		return;

	sMarkerSetDescription* pMS = pBodyDefs->arrDataDescriptions[0].Data.MarkerSetDescription;

	fprintf(fp, "<MarkerSet>\n\n");
	fprintf(fp, "<Name>\n%s\n</Name>\n\n", pMS->szName);

	fprintf(fp, "<Markers>\n");
	for (i = 0; i < pMS->nMarkers; i++)
	{
		fprintf(fp, "%s\n", pMS->szMarkerNames[i]);
	}
	fprintf(fp, "</Markers>\n\n");

	fprintf(fp, "<Data>\n");
	fprintf(fp, "Frame#\t");
	for (i = 0; i < pMS->nMarkers; i++)
	{
		fprintf(fp, "M%dX\tM%dY\tM%dZ\t", i, i, i);
	}
	fprintf(fp, "\n");

}


void _WriteFrame(FILE* fp, sFrameOfMocapData* data)
{
	fprintf(fp, "%d", data->iFrame);
	for (int i = 0; i < data->MocapData->nMarkers; i++)
	{
		fprintf(fp, "\t%.5f\t%.5f\t%.5f", data->MocapData->Markers[i][0], data->MocapData->Markers[i][1], data->MocapData->Markers[i][2]);
	}
	fprintf(fp, "\n");
}


void _WriteFooter(FILE* fp)
{
	fprintf(fp, "</Data>\n\n");
	fprintf(fp, "</MarkerSet>\n");
}


void resetClient()
{
	int iSuccess;

	printf("\n\nre-setting Client\n\n.");

	iSuccess = g_pClient->Disconnect();
	if (iSuccess != 0)
		printf("error un-initting Client\n");

	iSuccess = g_pClient->Connect(g_connectParams);
	if (iSuccess != 0)
		printf("error re-initting Client\n");
}


#ifndef _WIN32
char getch()
{
	char buf = 0;
	termios old = { 0 };

	fflush(stdout);

	if (tcgetattr(0, &old) < 0)
		perror("tcsetattr()");

	old.c_lflag &= ~ICANON;
	old.c_lflag &= ~ECHO;
	old.c_cc[VMIN] = 1;
	old.c_cc[VTIME] = 0;

	if (tcsetattr(0, TCSANOW, &old) < 0)
		perror("tcsetattr ICANON");

	if (read(0, &buf, 1) < 0)
		perror("read()");

	old.c_lflag |= ICANON;
	old.c_lflag |= ECHO;

	if (tcsetattr(0, TCSADRAIN, &old) < 0)
		perror("tcsetattr ~ICANON");

	//printf( "%c\n", buf );

	return buf;
}
#endif
