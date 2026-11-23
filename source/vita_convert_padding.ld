/* The Vita converter appends SCE module metadata to the first load segment.
   Here an inert 2 KiB zero-filled output section moves the following data
   segment to the next SDK page, leaving adequate room for the appended header. */
SECTIONS {
  .ina_link_padding : { BYTE(0); . += 0x7ff; }
}
INSERT AFTER .eh_frame;
