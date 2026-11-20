// colonelpanichacks/Sky-Spy: the callback queues detections and
// printerTask sends each one with send_json_fast.
struct id_data;
void send_json_fast(const id_data *UAV);
extern "C" void shim_sink(const void *item) { send_json_fast((const id_data *)item); }
