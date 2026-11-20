// colonelpanichacks/drone-mesh-mapper remoteid-mesh: the callback prints
// each detection itself (send_json_fast); nothing is queued.
extern "C" void shim_sink(const void *) {}
